//! Tests de integración de la feature `scan_submission`, `POST /api/scans`.
//!
//! Ejercen el router real de `gateway::api::app_router` servido sobre un
//! puerto efímero con `axum::serve` (mismo patrón que
//! `tests/usuarios_profile_proxy.rs`), con `AppState::usuarios_client`
//! apuntando a un stub HTTP real de `ms-usuarios` y
//! `AppState::broker_publisher` a un `gateway::sns::SnsScanPublisher`
//! real (o a un doble de prueba que nunca debe invocarse, según el
//! escenario) — nunca a `user-service`/a AWS (ver `docs/verification.md`
//! Nivel 3).
//!
//! Solo el escenario de "camino feliz" necesita un LocalStack real
//! (`testcontainers`, `#[ignore = "requiere Docker"]`, ver
//! `docs/conventions.md`): los otros escenarios (IP/CIDR inválido,
//! dependencia de `ms-usuarios` no disponible) nunca llegan a tocar el
//! Broker, así que corren en `cargo test` normal con un doble de prueba que
//! haría panic si se invocara.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::HeaderValue;
use axum::routing::{get, post};
use axum::{Json, Router};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{
    BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher, ROUTING_KEY_SCAN_REQUEST,
};
use gateway::domain::Session;
use gateway::realtime::RealtimeRegistry;
use gateway::sns::SnsScanPublisher;
use gateway::usuarios_client::UsuariosClient;
use secrecy::SecretString;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const MS_USUARIOS_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

/// Doble de prueba de [`ScanRequestPublisher`] para los escenarios que
/// nunca deben llegar a publicar en el Broker (IP/CIDR inválido, o
/// dependencia de `ms-usuarios` no disponible): si llegara a invocarse,
/// sería un bug del flujo bajo prueba, no un resultado esperado.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar una cancelación en el Broker");
    }
}

/// Doble de prueba de [`ScanRequestPublisher`] que siempre falla con
/// [`BrokerError::SnsPublishFailed`] (feature `log_broker_publish_errors`):
/// usado para confirmar que, tras agregar el error real del SDK al log del
/// servidor (`?err` en vez de `%err`, ver `src/api.rs`), la respuesta HTTP
/// hacia el cliente no cambia en absoluto — el `Display`/contrato externo de
/// `BrokerError` sigue intacto.
struct AlwaysFailsToPublish;

#[async_trait::async_trait]
impl ScanRequestPublisher for AlwaysFailsToPublish {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        Err(BrokerError::SnsPublishFailed {
            topic: "arn:aws:sns:us-east-1:000000000000:scan-requests".to_string(),
            source: "ChannelsLimitReached".into(),
        })
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar una cancelación en el Broker");
    }
}

/// Doble de prueba de [`ScanRequestPublisher`] que registra las `ip` de los
/// `ScanRequest` publicados (bug `scan_target_single_ip`: lo publicado debe
/// ser siempre una IP simple, nunca un CIDR).
#[derive(Default, Clone)]
struct RecordingPublisher {
    published_ips: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl ScanRequestPublisher for RecordingPublisher {
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError> {
        self.published_ips
            .lock()
            .expect("lock")
            .push(request.ip.clone());
        Ok(())
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no debe publicar una cancelación en el Broker");
    }
}

/// Stub de `ms-usuarios` que registra los `target` recibidos al resolver
/// credenciales y al registrar el histórico.
async fn spawn_recording_usuarios_stub(seen: Arc<Mutex<Vec<String>>>) -> String {
    #[derive(Clone)]
    struct Seen(Arc<Mutex<Vec<String>>>);

    async fn resolve(State(seen): State<Seen>, Query(q): Query<ScanTargetQuery>) -> Json<Value> {
        seen.0
            .lock()
            .expect("lock")
            .push(format!("resolve:{}", q.target));
        Json(json!({
            "network_user": "netuser-lab",
            "ssh_credentials_ref": "lab-only-not-a-real-secret",
            "has_sudo": true,
        }))
    }

    async fn history(State(seen): State<Seen>, Json(body): Json<Value>) -> Json<Value> {
        let target = body["target"].clone();
        seen.0
            .lock()
            .expect("lock")
            .push(format!("history:{}", target.as_str().unwrap_or_default()));
        Json(json!({
            "scan_id": "ms-usuarios-history-1",
            "user_id": "google-sub-123",
            "target": target,
            "status": "PENDIENTE",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }))
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");
    let app = Router::new()
        .route("/users/me/scan-targets", get(resolve))
        .route("/users/me/scans", post(history))
        .with_state(Seen(seen));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub ms-usuarios");
    });
    format!("http://{addr}")
}

async fn serve_discovery(State(issuer_url): State<String>) -> Json<Value> {
    Json(json!({
        "issuer": issuer_url,
        "authorization_endpoint": format!("{issuer_url}/authorize"),
        "token_endpoint": format!("{issuer_url}/token"),
        "jwks_uri": format!("{issuer_url}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn serve_empty_jwks() -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(jsonwebtoken::jwk::JwkSet { keys: vec![] })
}

/// IdP OIDC de prueba mínimo: esta feature no ejercita el login en sí, solo
/// necesita un `AppState` completo para poder construir `app_router` (mismo
/// patrón que `tests/usuarios_profile_proxy.rs`).
async fn spawn_discovery_only_idp() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del IdP de prueba");
    let addr = listener.local_addr().expect("addr del IdP de prueba");
    let issuer_url = format!("http://{addr}");

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(serve_discovery))
        .route("/jwks", get(serve_empty_jwks))
        .with_state(issuer_url.clone());

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del IdP de prueba");
    });

    issuer_url
}

/// URL base sobre la que no hay ningún servidor escuchando: simula
/// `ms-usuarios` completamente caído (mismo patrón que
/// `tests/usuarios_client.rs`).
async fn unreachable_usuarios_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temporal para reservar un puerto libre");
    let addr = listener.local_addr().expect("addr temporal");
    drop(listener);
    format!("http://{addr}")
}

/// Stub de `ms-usuarios` que **no implementa ninguna ruta**: cualquier
/// petición (incluida `GET /users/me/scan-targets`) recibe el `404` por
/// defecto de `axum`, tal como respondería hoy el `user-service` real, que
/// todavía no implementa esa API (ver `docs/architecture.md`
/// §"Dependencia pendiente").
async fn spawn_usuarios_stub_without_scan_target_api() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

/// Stub de `ms-usuarios` donde la API de resolución de credenciales de red
/// **existe** pero responde que no hay ninguna configurada para este
/// usuario/objetivo (`422`) — distinto del caso "la API no existe todavía"
/// (`404`, ver [`spawn_usuarios_stub_without_scan_target_api`]).
async fn spawn_usuarios_stub_with_scan_target_not_configured() -> String {
    async fn serve_unprocessable() -> axum::http::StatusCode {
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new().route("/users/me/scan-targets", get(serve_unprocessable));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

#[derive(Debug, serde::Deserialize)]
struct ScanTargetQuery {
    target: String,
}

async fn serve_scan_target_credentials(Query(query): Query<ScanTargetQuery>) -> Json<Value> {
    // El stub resuelve credenciales para cualquier `target`, pero exige que
    // la query llegue con ese parámetro (mismo contrato especulativo que
    // documenta `UsuariosClient::resolve_scan_target`).
    assert!(!query.target.is_empty());
    Json(json!({
        "network_user": "netuser-lab",
        "ssh_credentials_ref": "lab-only-not-a-real-secret",
        "has_sudo": true,
    }))
}

async fn serve_create_scan_history(Json(body): Json<Value>) -> Json<Value> {
    let target = body["target"].clone();
    Json(json!({
        "scan_id": "ms-usuarios-history-1",
        "user_id": "google-sub-123",
        "target": target,
        "status": "PENDIENTE",
        "requested_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }))
}

/// Stub de `ms-usuarios` que resuelve con éxito los 3 campos
/// (`network_user`/`ssh_credentials_ref`/`has_sudo`, contrato especulativo
/// asumido por `UsuariosClient::resolve_scan_target`, ver
/// `src/usuarios_client.rs`) y registra el histórico
/// (`POST /users/me/scans`, contrato real confirmado).
async fn spawn_happy_usuarios_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new()
        .route("/users/me/scan-targets", get(serve_scan_target_credentials))
        .route("/users/me/scans", post(serve_create_scan_history));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

struct GatewayUnderTest {
    addr: std::net::SocketAddr,
}

async fn spawn_gateway(
    usuarios_base_url: String,
    broker_publisher: Arc<dyn ScanRequestPublisher>,
) -> GatewayUnderTest {
    let issuer_url = spawn_discovery_only_idp().await;

    let oidc_client = OidcClient::discover(
        &issuer_url,
        TEST_CLIENT_ID,
        &SecretString::from("test-client-secret".to_string()),
        TEST_REDIRECT_URI,
    )
    .await
    .expect("discovery contra el IdP de prueba debe funcionar");

    let usuarios_client = UsuariosClient::new(
        usuarios_base_url,
        SecretString::from(MS_USUARIOS_SHARED_SECRET.to_string()),
    )
    .expect("cliente de laboratorio hacia ms-usuarios debe construirse");

    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: SecretString::from(SESSION_SIGNING_KEY.to_string()),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        front_base_url: "https://front.lab".to_string(),
        front_origin: HeaderValue::from_static("https://front.lab"),
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher,
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
        scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(
            1000,
            Duration::from_secs(60),
        )),
    };

    let app = app_router(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del Gateway de prueba");
    let addr = listener.local_addr().expect("addr del Gateway de prueba");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del Gateway de prueba");
    });

    GatewayUnderTest { addr }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior al epoch")
        .as_secs()
}

fn valid_session_cookie_value() -> String {
    let session = Session {
        sub: "google-sub-123".to_string(),
        email: "user@example.com".to_string(),
        name: "Test User".to_string(),
        exp: now_epoch_secs() + 3600,
    };

    issue_session_token(
        &session,
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("debe poder firmar una sesión de laboratorio válida")
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("cliente http de prueba")
}

#[tokio::test]
async fn scan_submission_rejects_invalid_target_without_touching_ms_usuarios_or_broker() {
    // Apunta a una URL sobre la que no hay nada escuchando: si la
    // validación no cortara antes de cualquier llamada externa, el intento
    // de contactar a ms-usuarios fallaría de un modo distinto a 400,
    // delatando el bug.
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;
    let http = http_client();

    let response = http
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": "not-an-ip" }))
        .send()
        .await
        .expect("POST /api/scans debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let body = response.text().await.expect("debe poder leer el cuerpo");
    assert!(
        body.contains("not-an-ip"),
        "el mensaje de error debe ser específico sobre el valor inválido: {body}"
    );
}

async fn post_target(gateway: &GatewayUnderTest, target: &str) -> reqwest::Response {
    http_client()
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": target }))
        .send()
        .await
        .expect("POST /api/scans debe responder")
}

#[tokio::test]
async fn scan_submission_publishes_and_records_the_bare_ip_for_single_host_targets() {
    let cases = [
        ("192.0.2.10", "192.0.2.10"),
        ("172.31.86.37/32", "172.31.86.37"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8::1/128", "2001:db8::1"),
    ];
    for (input, expected_ip) in cases {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let publisher = RecordingPublisher::default();
        let usuarios_base_url = spawn_recording_usuarios_stub(seen.clone()).await;
        let gateway = spawn_gateway(usuarios_base_url, Arc::new(publisher.clone())).await;

        let response = post_target(&gateway, input).await;

        assert_eq!(response.status(), reqwest::StatusCode::OK, "target {input}");
        assert_eq!(
            *publisher.published_ips.lock().expect("lock"),
            vec![expected_ip.to_string()],
            "el ScanRequest debe llevar la IP simple para {input}"
        );
        assert!(
            expected_ip.parse::<std::net::IpAddr>().is_ok(),
            "la ip publicada debe parsear como IpAddr"
        );
        assert_eq!(
            *seen.lock().expect("lock"),
            vec![
                format!("resolve:{expected_ip}"),
                format!("history:{expected_ip}")
            ],
            "ms-usuarios debe recibir la IP simple para {input}"
        );
    }
}

#[tokio::test]
async fn scan_submission_rejects_ranges_wider_than_a_single_host_with_400() {
    for target in ["10.0.0.0/24", "2001:db8::/64"] {
        let usuarios_base_url = unreachable_usuarios_base_url().await;
        let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;

        let response = post_target(&gateway, target).await;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{target}"
        );
        let body = response.text().await.expect("cuerpo");
        assert!(body.contains(target), "{body}");
        assert!(body.contains("una única IP"), "{body}");
    }
}

#[tokio::test]
async fn scan_submission_returns_an_explicit_error_when_ms_usuarios_scan_target_api_is_unavailable()
{
    let usuarios_base_url = spawn_usuarios_stub_without_scan_target_api().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;
    let http = http_client();

    let response = http
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": "10.0.0.5" }))
        .send()
        .await
        .expect("POST /api/scans debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn scan_submission_returns_an_explicit_error_when_ms_usuarios_has_no_credentials_configured()
{
    let usuarios_base_url = spawn_usuarios_stub_with_scan_target_not_configured().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;
    let http = http_client();

    let response = http
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": "10.0.0.5" }))
        .send()
        .await
        .expect("POST /api/scans debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error()
{
    // `ms-usuarios` resuelve los 3 campos y registra el histórico
    // normalmente (camino feliz hasta justo antes de publicar) — el único
    // fallo es el publicador del Broker, para aislar exclusivamente el
    // contrato HTTP de `ScanSubmitError::Broker` (feature
    // `log_broker_publish_errors`).
    let usuarios_base_url = spawn_happy_usuarios_stub().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(AlwaysFailsToPublish)).await;
    let http = http_client();

    let response = http
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": "192.0.2.10" }))
        .send()
        .await
        .expect("POST /api/scans debe responder");

    // Mismo status/cuerpo que antes de agregar `?err` al log del servidor:
    // el cambio de esta feature es exclusivamente qué llega al logger, nunca
    // el `Display`/contrato externo de `BrokerError` (criterio de aceptación
    // 1 y 3 de `log_broker_publish_errors`).
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body = response.text().await.expect("debe poder leer el cuerpo");
    assert_eq!(body, "no se pudo encolar la solicitud de escaneo");
    // La causa interna del SDK (`ChannelsLimitReached`, elegida arbitrariamente
    // para este test) nunca debe filtrarse al cliente HTTP.
    assert!(!body.contains("ChannelsLimitReached"));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_submission_happy_path_publishes_a_valid_scan_request_and_returns_the_scan_id() {
    let localstack = common::LocalStack::start().await;
    // Cola de verificación ad-hoc suscrita (raw) al topic de solicitudes: lo
    // que llega es exactamente lo que el Gateway publicó en SNS.
    let (requests_arn, requests_queue) = localstack.topic_with_queue("scan-requests").await;
    let (cancellations_arn, _cancellations_queue) =
        localstack.topic_with_queue("scan-cancellations").await;

    // Publicador real de producción sobre SNS.
    let broker_publisher: Arc<dyn ScanRequestPublisher> = Arc::new(SnsScanPublisher::from_client(
        localstack.sns.clone(),
        requests_arn,
        cancellations_arn,
    ));

    let usuarios_base_url = spawn_happy_usuarios_stub().await;
    let gateway = spawn_gateway(usuarios_base_url, broker_publisher).await;
    let http = http_client();

    let response = http
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .json(&json!({ "target": "192.0.2.10" }))
        .send()
        .await
        .expect("POST /api/scans debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.expect("cuerpo JSON válido");
    let scan_id = body["scanId"]
        .as_str()
        .expect("la respuesta debe traer scanId")
        .to_string();
    assert!(!scan_id.is_empty());

    let delivery = localstack
        .receive_one(&requests_queue)
        .await
        .expect("debe llegar un mensaje a la cola de verificación");
    assert_eq!(
        common::routing_key_of(&delivery),
        ROUTING_KEY_SCAN_REQUEST,
        "el ScanRequest debe viajar con el atributo routing_key=scan.request"
    );

    let scan_request: HashMap<String, Value> =
        serde_json::from_str(delivery.body().expect("cuerpo del mensaje"))
            .expect("el mensaje debe ser JSON válido");

    assert_eq!(scan_request["correlation_id"], json!(scan_id));
    assert_eq!(scan_request["ip"], json!("192.0.2.10"));
    assert_eq!(scan_request["network_user"], json!("netuser-lab"));
    assert_eq!(
        scan_request["ssh_credentials_ref"],
        json!("lab-only-not-a-real-secret")
    );
    assert_eq!(scan_request["has_sudo"], json!(true));
    assert_eq!(scan_request["requested_by"], json!("google-sub-123"));

    let expected_keys = [
        "correlation_id",
        "ip",
        "network_user",
        "ssh_credentials_ref",
        "has_sudo",
        "requested_by",
    ];
    assert_eq!(
        scan_request.len(),
        expected_keys.len(),
        "el ScanRequest publicado no debe traer campos extra (additionalProperties: false)"
    );
}
