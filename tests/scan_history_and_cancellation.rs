//! Tests de integración de la feature `scan_history_and_cancellation`.
//!
//! - `GET /api/scans` (histórico): ejerce el router real de
//!   `gateway::api::app_router` contra un stub HTTP real de `ms-usuarios`
//!   (`GET /users/me/scans`), con `AppState::scan_ownership` poblado a mano
//!   para verificar tanto el caso con `scanId` propio conocido como el caso
//!   sin mapeo (campo ausente). No necesita Docker.
//! - `POST /api/scans/{scan_id}/cancel` de un scan ajeno o inexistente (404)
//!   y de un scan ya terminado (409, sin publicar nada) tampoco necesitan
//!   Docker: nunca llegan a publicar en el Broker (doble de prueba que haría
//!   panic si se invocara).
//! - `POST /api/scans/{scan_id}/cancel` de un scan propio en curso sí
//!   necesita un RabbitMQ real (`testcontainers`,
//!   `#[ignore = "requiere Docker"]`, ver `docs/conventions.md`): publica de
//!   verdad un `ScanCancellation` y lo verifica contra una cola de prueba
//!   bindeada a `scan.cancellations`/`scan.cancellation`, mismo patrón que
//!   `tests/scan_submission.rs`.

use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{
    BrokerError, BrokerPublisher, ScanCancellation, ScanRequest, ScanRequestPublisher,
};
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

const VHOST: &str = "security-app";
const GATEWAY_RABBITMQ_USER: &str = "gateway";
const GATEWAY_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret-gateway";
const ADMIN_RABBITMQ_USER: &str = "lab-admin";
const ADMIN_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret";

/// Doble de prueba de [`ScanRequestPublisher`]: los escenarios que nunca
/// deben llegar a publicar nada en el Broker (scan ajeno/inexistente, scan
/// ya terminado) usan este doble, que haría panic si se invocara.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar un ScanRequest en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no debe llegar a publicar una cancelación en el Broker");
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

/// IdP OIDC de prueba mínimo: estos tests no ejercitan el login en sí, solo
/// necesitan un `AppState` completo para poder construir `app_router` (mismo
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

/// Stub de `ms-usuarios` que sirve `GET /users/me/scans` devolviendo
/// `history` tal cual, sin validar credenciales (los tests que sí ejercen
/// ese camino viven en `tests/usuarios_client.rs`).
async fn spawn_usuarios_history_stub(history: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new().route("/users/me/scans", get(move || async move { Json(history) }));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

struct GatewayUnderTest {
    addr: std::net::SocketAddr,
    scan_ownership: Arc<ScanOwnershipRegistry>,
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

    let scan_ownership = Arc::new(ScanOwnershipRegistry::new());

    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: SecretString::from(SESSION_SIGNING_KEY.to_string()),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher,
        scan_ownership: scan_ownership.clone(),
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

    GatewayUnderTest {
        addr,
        scan_ownership,
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior al epoch")
        .as_secs()
}

fn session_for(sub: &str) -> Session {
    Session {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
        name: "Test User".to_string(),
        exp: now_epoch_secs() + 3600,
    }
}

fn session_cookie_value_for(sub: &str) -> String {
    issue_session_token(
        &session_for(sub),
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
async fn scan_history_returns_the_entries_of_the_active_session_with_and_without_known_scan_id() {
    let history = json!([
        {
            "scan_id": "ms-usuarios-known",
            "user_id": "alice",
            "target": "192.0.2.10",
            "status": "EN_PROGRESO",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:05:00Z",
        },
        {
            "scan_id": "ms-usuarios-unknown",
            "user_id": "alice",
            "target": "192.0.2.20",
            "status": "COMPLETADO",
            "requested_at": "2024-01-02T00:00:00Z",
            "updated_at": "2024-01-02T01:00:00Z",
        },
    ]);
    let usuarios_base_url = spawn_usuarios_history_stub(history).await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;

    // Solo la primera entrada tiene un `scanId` propio todavía registrado
    // (simula un proceso que no se reinició desde que se publicó ese
    // escaneo); la segunda simula la limitación documentada de
    // `ScanOwnershipRegistry` (sin mapeo conocido).
    gateway.scan_ownership.register(
        "gateway-scan-id-known",
        "ms-usuarios-known".to_string(),
        session_for("alice"),
    );

    let http = http_client();
    let response = http
        .get(format!("http://{}/api/scans", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!(
                "{SESSION_COOKIE_NAME}={}",
                session_cookie_value_for("alice")
            ),
        )
        .send()
        .await
        .expect("GET /api/scans debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.expect("cuerpo JSON válido");
    let entries = body.as_array().expect("debe ser un array JSON");
    assert_eq!(entries.len(), 2);

    let known = &entries[0];
    assert_eq!(known["scanId"], json!("gateway-scan-id-known"));
    assert_eq!(known["target"], json!("192.0.2.10"));
    assert_eq!(known["status"], json!("EN_PROGRESO"));

    let unknown = &entries[1];
    assert!(
        unknown.get("scanId").is_none(),
        "una entrada sin scanId propio conocido no debe traer ese campo: {unknown}"
    );
    assert_eq!(unknown["target"], json!("192.0.2.20"));
    assert_eq!(unknown["status"], json!("COMPLETADO"));
}

#[tokio::test]
async fn cancel_scan_owned_by_another_session_returns_not_found() {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;

    gateway.scan_ownership.register(
        "scan-owned-by-alice",
        "ms-usuarios-1".to_string(),
        session_for("alice"),
    );

    let http = http_client();
    let response = http
        .post(format!(
            "http://{}/api/scans/scan-owned-by-alice/cancel",
            gateway.addr
        ))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", session_cookie_value_for("bob")),
        )
        .send()
        .await
        .expect("POST /api/scans/.../cancel debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_scan_that_does_not_exist_returns_not_found() {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;

    let http = http_client();
    let response = http
        .post(format!(
            "http://{}/api/scans/no-existe/cancel",
            gateway.addr
        ))
        .header(
            reqwest::header::COOKIE,
            format!(
                "{SESSION_COOKIE_NAME}={}",
                session_cookie_value_for("alice")
            ),
        )
        .send()
        .await
        .expect("POST /api/scans/.../cancel debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_scan_already_in_a_terminal_state_is_rejected_without_publishing() {
    let history = json!([
        {
            "scan_id": "ms-usuarios-done",
            "user_id": "alice",
            "target": "192.0.2.10",
            "status": "COMPLETADO",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:05:00Z",
        },
    ]);
    let usuarios_base_url = spawn_usuarios_history_stub(history).await;
    let gateway = spawn_gateway(usuarios_base_url, Arc::new(NeverPublishesToBroker)).await;

    gateway.scan_ownership.register(
        "scan-already-done",
        "ms-usuarios-done".to_string(),
        session_for("alice"),
    );

    let http = http_client();
    let response = http
        .post(format!(
            "http://{}/api/scans/scan-already-done/cancel",
            gateway.addr
        ))
        .header(
            reqwest::header::COOKIE,
            format!(
                "{SESSION_COOKIE_NAME}={}",
                session_cookie_value_for("alice")
            ),
        )
        .send()
        .await
        .expect("POST /api/scans/.../cancel debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
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
/// topología copiada literalmente de `broker/rabbitmq/definitions.json` (ver
/// `docs/architecture.md`) — mismo helper que `tests/scan_submission.rs`.
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

/// Conexión AMQPS "a mano" (sin pasar por `gateway::broker`, que solo expone
/// publicar) usada por el test para preparar/leer la cola de verificación
/// con el usuario `lab-admin` (ver
/// `progress/explore_lapin_testcontainers.md` §3: el usuario `gateway` tiene
/// `configure: "^$"`, no puede declarar nada).
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
async fn cancel_scan_owned_and_in_progress_publishes_a_valid_scan_cancellation() {
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
    // ad-hoc de este test (nunca la declara el código de producción, que usa
    // el usuario `gateway`, sin permiso `configure`).
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
            "test.scan-cancellations-verify",
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
            "test.scan-cancellations-verify",
            "scan.cancellations",
            "scan.cancellation",
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
            "test.scan-cancellations-verify",
            "test-consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("consumir la cola de verificación de prueba");

    // Publicador real de producción, conectado como el usuario `gateway`
    // (mínimo privilegio: `write` sobre `scan.requests`/`scan.cancellations`).
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

    let history = json!([
        {
            "scan_id": "ms-usuarios-in-progress",
            "user_id": "alice",
            "target": "192.0.2.10",
            "status": "EN_PROGRESO",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:05:00Z",
        },
    ]);
    let usuarios_base_url = spawn_usuarios_history_stub(history).await;
    let gateway = spawn_gateway(usuarios_base_url, broker_publisher).await;

    const SCAN_ID: &str = "gateway-scan-id-in-progress";
    gateway.scan_ownership.register(
        SCAN_ID,
        "ms-usuarios-in-progress".to_string(),
        session_for("alice"),
    );

    let http = http_client();
    let response = http
        .post(format!(
            "http://{}/api/scans/{SCAN_ID}/cancel",
            gateway.addr
        ))
        .header(
            reqwest::header::COOKIE,
            format!(
                "{SESSION_COOKIE_NAME}={}",
                session_cookie_value_for("alice")
            ),
        )
        .send()
        .await
        .expect("POST /api/scans/.../cancel debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);

    let delivery = tokio::time::timeout(Duration::from_secs(10), consumer.next())
        .await
        .expect("no debe hacer timeout esperando el ScanCancellation publicado")
        .expect("debe llegar un mensaje a la cola de verificación")
        .expect("sin error de protocolo AMQP");

    let scan_cancellation: HashMap<String, Value> =
        serde_json::from_slice(&delivery.data).expect("el mensaje debe ser JSON válido");

    assert_eq!(scan_cancellation["correlation_id"], json!(SCAN_ID));
    assert_eq!(scan_cancellation["requested_by"], json!("alice"));

    let expected_keys = ["correlation_id", "requested_by"];
    assert_eq!(
        scan_cancellation.len(),
        expected_keys.len(),
        "el ScanCancellation publicado no debe traer campos extra (additionalProperties: false)"
    );

    delivery
        .acker
        .ack(BasicAckOptions::default())
        .await
        .expect("debe poder confirmar el mensaje consumido");
}
