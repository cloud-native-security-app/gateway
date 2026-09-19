//! Tests de integración de la feature `scan_submission`, `POST /api/scans`.
//!
//! Ejercen el router real de `gateway::api::app_router` servido sobre un
//! puerto efímero con `axum::serve` (mismo patrón que
//! `tests/usuarios_profile_proxy.rs`), con `AppState::usuarios_client`
//! apuntando a un stub HTTP real de `ms-usuarios` y
//! `AppState::broker_publisher` a un `gateway::broker::BrokerPublisher`
//! real (o a un doble de prueba que nunca debe invocarse, según el
//! escenario) — nunca a `user-service`/al Broker de producción (ver
//! `docs/verification.md` Nivel 3).
//!
//! Solo el escenario de "camino feliz" necesita un RabbitMQ real
//! (`testcontainers`, `#[ignore = "requiere Docker"]`, ver
//! `docs/conventions.md`): los otros dos escenarios (IP/CIDR inválido,
//! dependencia de `ms-usuarios` no disponible) nunca llegan a tocar el
//! Broker, así que corren en `cargo test` normal con un doble de prueba que
//! haría panic si se invocara.

use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, BrokerPublisher, ScanRequest, ScanRequestPublisher};
use gateway::domain::Session;
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::UsuariosClient;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ConfirmSelectOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::{Connection, ConnectionProperties};
use secrecy::SecretString;
use serde_json::{json, Value};
use std::collections::HashMap;
use testcontainers::core::{IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const MS_USUARIOS_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

/// Credenciales de laboratorio del usuario RabbitMQ `gateway`, copiadas de
/// `broker/rabbitmq/README.md` (tabla "Credenciales de laboratorio") — el
/// mismo usuario ya definido en `broker/rabbitmq/definitions.json`, con
/// permiso `write` solo sobre `scan.requests`/`scan.cancellations`.
const GATEWAY_RABBITMQ_USER: &str = "gateway";
const GATEWAY_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret-gateway";

/// Credenciales de laboratorio del usuario administrador de RabbitMQ, único
/// con permiso para declarar/bindear la cola de verificación de este test
/// (el usuario `gateway` tiene `configure: "^$"`, no puede declarar nada —
/// ver `progress/explore_lapin_testcontainers.md` §3).
const ADMIN_RABBITMQ_USER: &str = "lab-admin";
const ADMIN_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret";

const VHOST: &str = "security-app";

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
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher,
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
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

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

static CRYPTO_PROVIDER_INIT: Once = Once::new();

fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        // Instalación defensiva del backend criptográfico de `rustls`, ver
        // `progress/explore_lapin_testcontainers.md` §4.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Levanta un `rabbitmq:4.3.5-management` real vía `testcontainers`, con la
/// topología copiada literalmente de `broker/rabbitmq/definitions.json`
/// (ver `docs/architecture.md`) y TLS habilitado con los certificados de
/// laboratorio también copiados de `broker/rabbitmq/tls/`.
async fn start_rabbitmq() -> ContainerAsync<GenericImage> {
    install_crypto_provider_once();

    GenericImage::new("rabbitmq", "4.3.5-management")
        .with_exposed_port(5672.tcp())
        .with_exposed_port(5671.tcp())
        .with_exposed_port(15672.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/definitions.json")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/definitions.json",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/rabbitmq.conf")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/rabbitmq.conf",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/ca_certificate.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/ca_certificate.pem",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/server_certificate.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/server_certificate.pem",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/server_key.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/server_key.pem",
        ))
        .start()
        .await
        .expect("el contenedor RabbitMQ de test debe arrancar")
}

/// Conexión AMQPS "a mano" (sin pasar por `gateway::broker`, que solo
/// expone publicar) usada por el test para preparar/leer la cola de
/// verificación con el usuario `lab-admin` (ver
/// `progress/explore_lapin_testcontainers.md` §3: el usuario `gateway`
/// tiene `configure: "^$"`, no puede declarar nada).
async fn connect_lapin_as(
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    ca_pem: &str,
) -> Connection {
    let uri = format!("amqps://{user}:{password}@{host}:{port}/{VHOST}");
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);
    let tls_config = OwnedTLSConfig {
        identity: None,
        cert_chain: Some(ca_pem.to_string()),
    };

    Connection::connect_with_config(&uri, options, tls_config)
        .await
        .expect("la conexión AMQPS de prueba debe completarse")
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_submission_happy_path_publishes_a_valid_scan_request_and_returns_the_scan_id() {
    let container = start_rabbitmq().await;
    let host = container
        .get_host()
        .await
        .expect("host del contenedor de prueba")
        .to_string();
    let amqps_port = container
        .get_host_port_ipv4(5671.tcp())
        .await
        .expect("puerto AMQPS publicado del contenedor de prueba");

    let ca_pem = std::fs::read_to_string(fixture_path("rabbitmq/tls/ca_certificate.pem"))
        .expect("debe poder leer la CA de laboratorio");

    // Conexión de administración: declara y bindea la cola de verificación
    // ad-hoc de este test (nunca la declara el código de producción, que
    // usa el usuario `gateway`, sin permiso `configure`).
    let admin_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
        &ca_pem,
    )
    .await;
    let admin_channel = admin_connection
        .create_channel()
        .await
        .expect("canal de administración de prueba");

    admin_channel
        .queue_declare(
            "test.scan-requests-verify",
            QueueDeclareOptions {
                durable: false,
                exclusive: true,
                auto_delete: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("declarar la cola de verificación de prueba");

    admin_channel
        .queue_bind(
            "test.scan-requests-verify",
            "scan.requests",
            "scan.request",
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("bindear la cola de verificación de prueba");

    admin_channel
        .confirm_select(ConfirmSelectOptions::default())
        .await
        .expect("confirm_select del canal de administración");

    let mut consumer = admin_channel
        .basic_consume(
            "test.scan-requests-verify",
            "test-consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("consumir la cola de verificación de prueba");

    // Publicador real de producción, conectado como el usuario `gateway`
    // (mínimo privilegio: solo `write` en `scan.requests`).
    let broker_publisher: Arc<dyn ScanRequestPublisher> = Arc::new(
        BrokerPublisher::connect_with_ca_pem(
            &SecretString::from(format!(
                "amqps://{GATEWAY_RABBITMQ_USER}:{GATEWAY_RABBITMQ_PASSWORD}@{host}:{amqps_port}"
            )),
            VHOST,
            ca_pem,
        )
        .await
        .expect("BrokerPublisher debe poder conectar contra el RabbitMQ de prueba"),
    );

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

    let delivery = tokio::time::timeout(Duration::from_secs(10), consumer.next())
        .await
        .expect("no debe hacer timeout esperando el ScanRequest publicado")
        .expect("debe llegar un mensaje a la cola de verificación")
        .expect("sin error de protocolo AMQP");

    let scan_request: HashMap<String, Value> =
        serde_json::from_slice(&delivery.data).expect("el mensaje debe ser JSON válido");

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

    delivery
        .acker
        .ack(BasicAckOptions::default())
        .await
        .expect("debe poder confirmar el mensaje consumido");
}
