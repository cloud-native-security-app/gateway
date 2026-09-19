//! Tests de integración de la feature `rate_limiting`, el límite de tasa por
//! usuario (RF-12) aplicado a `POST /api/scans`.
//!
//! Ejercen el router real de `gateway::api::app_router` servido sobre un
//! puerto efímero con `axum::serve` (mismo patrón que
//! `tests/scan_submission.rs`), con un doble de [`ScanRequestPublisher`] que
//! siempre confirma la publicación (esta feature no ejercita el Broker real:
//! eso ya lo cubre `tests/scan_submission.rs`) y un stub de `ms-usuarios`
//! que siempre resuelve las credenciales de red y registra el histórico, de
//! modo que la única variable bajo prueba sea el rate limiter. No requiere
//! Docker.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::Session;
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::UsuariosClient;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const MS_USUARIOS_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

/// Doble de [`ScanRequestPublisher`] que siempre confirma la publicación:
/// esta feature no ejercita el contrato publicado en el Broker (ya cubierto
/// por `tests/scan_submission.rs`), solo que el rate limiter deje pasar o
/// rechace la solicitud antes de llegar aquí.
struct AlwaysSucceedsPublisher;

#[async_trait::async_trait]
impl ScanRequestPublisher for AlwaysSucceedsPublisher {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        Ok(())
    }
}

/// Doble de [`ScanRequestPublisher`] que hace panic si se invoca: usado en
/// el escenario que verifica que una solicitud rechazada por el rate
/// limiter nunca llega a publicar en el Broker.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!(
            "una solicitud rechazada por el rate limiter no debe llegar a publicar en el Broker"
        );
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar una cancelación en el Broker");
    }
}

/// URL base sobre la que no hay ningún servidor escuchando: simula
/// `ms-usuarios` completamente caído. Si el rate limiter no cortara antes de
/// que el handler llame a `ms-usuarios`, la solicitud fallaría con un status
/// de error de red (502/504), no con 429, delatando el bug.
async fn unreachable_usuarios_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temporal para reservar un puerto libre");
    let addr = listener.local_addr().expect("addr temporal");
    drop(listener);
    format!("http://{addr}")
}

async fn serve_discovery(
    axum::extract::State(issuer_url): axum::extract::State<String>,
) -> Json<Value> {
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
/// patrón que `tests/scan_submission.rs`).
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

#[derive(Debug, serde::Deserialize)]
struct ScanTargetQuery {
    target: String,
}

async fn serve_scan_target_credentials(Query(query): Query<ScanTargetQuery>) -> Json<Value> {
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
        "scan_id": format!("ms-usuarios-history-{}", uuid::Uuid::new_v4()),
        "user_id": "google-sub-123",
        "target": target,
        "status": "PENDIENTE",
        "requested_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }))
}

/// Stub de `ms-usuarios` que siempre resuelve con éxito los 3 campos de
/// credenciales de red y registra el histórico (mismo contrato especulativo
/// que `tests/scan_submission.rs`).
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

/// Levanta un Gateway de prueba completo con un rate limiter de
/// `max_requests`/`window` configurable (feature `rate_limiting`), un stub
/// de `ms-usuarios` que siempre resuelve, y un publicador del Broker que
/// siempre confirma.
async fn spawn_gateway(max_requests: u32, window: Duration) -> GatewayUnderTest {
    let usuarios_base_url = spawn_happy_usuarios_stub().await;
    spawn_gateway_with(
        max_requests,
        window,
        usuarios_base_url,
        Arc::new(AlwaysSucceedsPublisher),
    )
    .await
}

/// Igual que [`spawn_gateway`], pero permitiendo inyectar el `usuarios_base_url`
/// y el publicador del Broker: usado por el test que verifica que una
/// solicitud rechazada por el rate limiter nunca llega a tocar ni
/// `ms-usuarios` ni el Broker.
async fn spawn_gateway_with(
    max_requests: u32,
    window: Duration,
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
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher,
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
        scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(
            max_requests,
            window,
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

/// Emite la cookie de sesión de laboratorio para un `sub` dado: cada usuario
/// distinto usado en estos tests tiene su propia identidad de sesión, que es
/// la clave del rate limiter (nunca la IP, ver `docs/security-scope.md`).
fn session_cookie_value_for(sub: &str) -> String {
    let session = Session {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
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

async fn submit_scan(
    http: &reqwest::Client,
    addr: std::net::SocketAddr,
    session_cookie: &str,
    target: &str,
) -> reqwest::StatusCode {
    http.post(format!("http://{addr}/api/scans"))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={session_cookie}"),
        )
        .json(&json!({ "target": target }))
        .send()
        .await
        .expect("POST /api/scans debe responder")
        .status()
}

#[tokio::test]
async fn user_exceeding_the_threshold_receives_429_on_the_request_that_exceeds_it() {
    let gateway = spawn_gateway(2, Duration::from_secs(60)).await;
    let http = http_client();
    let session_cookie = session_cookie_value_for("google-sub-rl-1");

    let first = submit_scan(&http, gateway.addr, &session_cookie, "192.0.2.10").await;
    let second = submit_scan(&http, gateway.addr, &session_cookie, "192.0.2.11").await;
    let third = submit_scan(&http, gateway.addr, &session_cookie, "192.0.2.12").await;

    assert_eq!(first, reqwest::StatusCode::OK, "la 1ª solicitud debe pasar");
    assert_eq!(
        second,
        reqwest::StatusCode::OK,
        "la 2ª solicitud (igual al umbral) debe pasar"
    );
    assert_eq!(
        third,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "la 3ª solicitud, que supera el umbral, debe rechazarse con 429"
    );
}

#[tokio::test]
async fn a_second_user_in_parallel_is_not_affected_by_another_users_limit() {
    let gateway = spawn_gateway(1, Duration::from_secs(60)).await;
    let http = http_client();
    let session_a = session_cookie_value_for("google-sub-rl-a");
    let session_b = session_cookie_value_for("google-sub-rl-b");

    // El usuario A agota su único cupo permitido...
    let a_first = submit_scan(&http, gateway.addr, &session_a, "192.0.2.20").await;
    assert_eq!(a_first, reqwest::StatusCode::OK);

    // ...y su segunda solicitud (en paralelo con la primera del usuario B)
    // se rechaza, mientras que la del usuario B, con contador
    // independiente, sigue pasando con normalidad (RF-12, criterio de
    // aceptación 4/5: contadores independientes por usuario).
    let (a_second, b_first) = tokio::join!(
        submit_scan(&http, gateway.addr, &session_a, "192.0.2.21"),
        submit_scan(&http, gateway.addr, &session_b, "192.0.2.22"),
    );

    assert_eq!(
        a_second,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "el usuario A ya agotó su cupo"
    );
    assert_eq!(
        b_first,
        reqwest::StatusCode::OK,
        "el límite del usuario A no debe afectar al usuario B"
    );
}

#[tokio::test]
async fn exceeding_the_limit_never_reaches_ms_usuarios_or_the_broker() {
    // Umbral 0: la primera solicitud ya lo supera. `ms-usuarios` está
    // inalcanzable y el publicador del Broker hace panic si se invoca: si el
    // rate limiter no cortara antes que el resto del handler, este test
    // fallaría (por panic o por un status de error de red) en vez de recibir
    // 429.
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway_with(
        0,
        Duration::from_secs(60),
        usuarios_base_url,
        Arc::new(NeverPublishesToBroker),
    )
    .await;
    let http = http_client();
    let session_cookie = session_cookie_value_for("google-sub-rl-zero");

    let status = submit_scan(&http, gateway.addr, &session_cookie, "192.0.2.30").await;

    assert_eq!(status, reqwest::StatusCode::TOO_MANY_REQUESTS);
}
