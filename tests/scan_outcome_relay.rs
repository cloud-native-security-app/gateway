//! Tests de integración de la feature `scan_outcome_relay`.
//!
//! - `sse_events_rejects_a_scan_id_owned_by_another_session` y
//!   `sse_events_rejects_an_unknown_scan_id` no necesitan Docker: ejercen el
//!   router real (`gateway::api::app_router`) con
//!   `AppState::scan_ownership` poblado a mano, sin pasar por el Broker.
//! - `consumes_scan_outcomes_from_a_real_queue_and_relays_them_via_sse_in_order_until_terminal_state`
//!   necesita un RabbitMQ real (`testcontainers`, `#[ignore = "requiere
//!   Docker"]`, ver `docs/conventions.md`): publica manualmente
//!   `started`/completed`/`failed` (y un mensaje malformado de por medio,
//!   para verificar que no tumba el consumidor) en la cola de prueba
//!   bindeada exactamente como `gateway.scan-outcomes` en
//!   `broker/rabbitmq/definitions.json`, y verifica que el stream SSE los
//!   recibe en orden, que `ms-usuarios` se actualiza en cada paso, y que el
//!   stream se cierra al llegar al estado terminal.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use futures_util::StreamExt;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{
    BrokerConsumer, BrokerError, ScanCancellation, ScanOutcomeHandler, ScanRequest,
    ScanRequestPublisher,
};
use gateway::domain::{ScanOutcomeEvent, ScanResult, Session};
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::{ScanStatus, UsuariosClient};
use lapin::options::{BasicPublishOptions, ConfirmSelectOptions};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::{Connection, ConnectionProperties};
use secrecy::SecretString;
use serde_json::{json, Value};
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

/// Doble de prueba de [`ScanRequestPublisher`]: ninguno de estos tests
/// ejerce `POST /api/scans`.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("estos tests no deben llegar a publicar en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("estos tests no deben llegar a publicar una cancelación en el Broker");
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

/// Llamadas capturadas por [`spawn_usuarios_status_stub`]: `(scan_id,
/// status)` en el orden en que `PATCH /scans/{scan_id}` las recibió.
type CapturedStatusUpdates = Arc<Mutex<Vec<(String, String)>>>;

async fn serve_patch_scan_status(
    AxumPath(scan_id): AxumPath<String>,
    State(calls): State<CapturedStatusUpdates>,
    Json(body): Json<Value>,
) -> axum::http::StatusCode {
    let status = body["status"].as_str().unwrap_or_default().to_string();
    calls
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push((scan_id, status));
    axum::http::StatusCode::NO_CONTENT
}

/// Stub real de `ms-usuarios` que solo implementa `PATCH /scans/{scan_id}`
/// (lo único que ejerce esta feature), capturando cada llamada para poder
/// verificar el criterio de aceptación 2 (cada evento consumido actualiza el
/// estado en `ms-usuarios`).
async fn spawn_usuarios_status_stub() -> (String, CapturedStatusUpdates) {
    let calls: CapturedStatusUpdates = Arc::new(Mutex::new(Vec::new()));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new()
        .route("/scans/:scan_id", patch(serve_patch_scan_status))
        .with_state(calls.clone());

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    (format!("http://{addr}"), calls)
}

struct GatewayUnderTest {
    addr: SocketAddr,
    scan_ownership: Arc<ScanOwnershipRegistry>,
    realtime: Arc<RealtimeRegistry>,
}

async fn spawn_gateway(usuarios_client: UsuariosClient) -> GatewayUnderTest {
    let issuer_url = spawn_discovery_only_idp().await;

    let oidc_client = OidcClient::discover(
        &issuer_url,
        TEST_CLIENT_ID,
        &SecretString::from("test-client-secret".to_string()),
        TEST_REDIRECT_URI,
    )
    .await
    .expect("discovery contra el IdP de prueba debe funcionar");

    let scan_ownership = Arc::new(ScanOwnershipRegistry::new());
    let realtime = Arc::new(RealtimeRegistry::new());

    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: SecretString::from(SESSION_SIGNING_KEY.to_string()),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher: Arc::new(NeverPublishesToBroker),
        scan_ownership: scan_ownership.clone(),
        realtime: realtime.clone(),
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

    GatewayUnderTest {
        addr,
        scan_ownership,
        realtime,
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

fn lab_usuarios_client(base_url: String) -> UsuariosClient {
    UsuariosClient::new(
        base_url,
        SecretString::from(MS_USUARIOS_SHARED_SECRET.to_string()),
    )
    .expect("cliente de laboratorio hacia ms-usuarios debe construirse")
}

async fn unreachable_usuarios_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temporal para reservar un puerto libre");
    let addr = listener.local_addr().expect("addr temporal");
    drop(listener);
    format!("http://{addr}")
}

#[tokio::test]
async fn sse_events_rejects_a_scan_id_owned_by_another_session() {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(lab_usuarios_client(usuarios_base_url)).await;

    gateway.scan_ownership.register(
        "scan-owned-by-alice",
        "ms-usuarios-1".to_string(),
        session_for("alice"),
    );

    let http = http_client();
    let response = http
        .get(format!(
            "http://{}/api/scans/scan-owned-by-alice/events",
            gateway.addr
        ))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", session_cookie_value_for("bob")),
        )
        .send()
        .await
        .expect("GET /api/scans/.../events debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sse_events_rejects_an_unknown_scan_id() {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(lab_usuarios_client(usuarios_base_url)).await;

    let http = http_client();
    let response = http
        .get(format!(
            "http://{}/api/scans/no-existe/events",
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
        .expect("GET /api/scans/.../events debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

/// Puente entre [`BrokerConsumer`] y el resto del Gateway bajo prueba: igual
/// lógica que `gateway::wiring::ScanOutcomeRelay` (privada a ese módulo),
/// reconstruida aquí con la API pública ([`ScanOutcomeHandler`],
/// [`RealtimeRegistry::publish`], [`UsuariosClient::update_scan_status`])
/// para ejercer el mismo camino que corre en producción.
struct TestRelayHandler {
    usuarios_client: Arc<UsuariosClient>,
    scan_ownership: Arc<ScanOwnershipRegistry>,
    realtime: Arc<RealtimeRegistry>,
}

#[async_trait::async_trait]
impl ScanOutcomeHandler for TestRelayHandler {
    async fn handle(&self, event: ScanOutcomeEvent) {
        self.realtime.publish(&event);

        if let Some(ownership) = self.scan_ownership.lookup(event.correlation_id()) {
            let status = match &event {
                ScanOutcomeEvent::Started { .. } => ScanStatus::EnProgreso,
                ScanOutcomeEvent::Completed { .. } => ScanStatus::Completado,
                ScanOutcomeEvent::Failed { .. } => ScanStatus::Fallido,
            };
            let _ = self
                .usuarios_client
                .update_scan_status(&ownership.owner, &ownership.ms_usuarios_scan_id, status)
                .await;
        }
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

static CRYPTO_PROVIDER_INIT: Once = Once::new();

fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Levanta un `rabbitmq:4.3.5-management` real vía `testcontainers`, con la
/// topología copiada literalmente de `broker/rabbitmq/definitions.json`
/// (ver `docs/architecture.md`) — mismo helper que
/// `tests/scan_submission.rs`.
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

/// Lee del stream de bytes hasta completar el próximo evento SSE (`\n\n`) y
/// devuelve la concatenación de sus líneas `data: `, o `None` si el stream
/// terminó sin más eventos.
async fn next_sse_data_field(
    stream: &mut (impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin),
    buffer: &mut String,
) -> Option<String> {
    loop {
        if let Some(pos) = buffer.find("\n\n") {
            let raw_event: String = buffer.drain(..pos + 2).collect();
            let data = raw_event
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("data: ")
                        .or_else(|| line.strip_prefix("data:"))
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !data.is_empty() {
                return Some(data);
            }
            continue;
        }
        match stream.next().await {
            Some(Ok(chunk)) => buffer.push_str(&String::from_utf8_lossy(&chunk)),
            _ => return None,
        }
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn consumes_scan_outcomes_from_a_real_queue_and_relays_them_via_sse_in_order_until_terminal_state(
) {
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

    let (usuarios_base_url, usuarios_calls) = spawn_usuarios_status_stub().await;
    let usuarios_client = Arc::new(lab_usuarios_client(usuarios_base_url));

    let gateway = spawn_gateway(
        UsuariosClient::new(
            "http://unused.invalid".to_string(),
            SecretString::from(MS_USUARIOS_SHARED_SECRET.to_string()),
        )
        .expect("cliente de laboratorio hacia ms-usuarios debe construirse"),
    )
    .await;

    const SCAN_ID: &str = "scan-int-test-1";
    gateway.scan_ownership.register(
        SCAN_ID,
        "ms-usuarios-scan-1".to_string(),
        session_for("alice"),
    );

    let scan_outcome_consumer = BrokerConsumer::connect_with_ca_pem(
        &SecretString::from(format!(
            "amqps://{GATEWAY_RABBITMQ_USER}:{GATEWAY_RABBITMQ_PASSWORD}@{host}:{amqps_port}"
        )),
        VHOST,
        ca_pem.clone(),
    )
    .await
    .expect("BrokerConsumer debe poder conectar contra el RabbitMQ de prueba");

    let handler: Arc<dyn ScanOutcomeHandler> = Arc::new(TestRelayHandler {
        usuarios_client,
        scan_ownership: gateway.scan_ownership.clone(),
        realtime: gateway.realtime.clone(),
    });
    tokio::spawn(scan_outcome_consumer.run(handler));

    // Cliente SSE, suscrito antes de que se publique nada: `subscribe_stream`
    // crea el canal en el registro al primer `GET`, y el consumidor de fondo
    // ya está corriendo (arriba), así que cualquier publicación posterior
    // debe llegarle.
    let http = http_client();
    let response = http
        .get(format!(
            "http://{}/api/scans/{SCAN_ID}/events",
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
        .expect("la conexión SSE debe aceptarse");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let mut byte_stream = response.bytes_stream();
    let mut buffer = String::new();

    // Admin: único usuario con permiso `configure` para declarar la cola de
    // prueba que consume el `BrokerConsumer` de arriba... en realidad el
    // `BrokerConsumer` ya consume `gateway.scan-outcomes` directamente (ya
    // declarada por la topología cargada al arrancar el contenedor, ver
    // `start_rabbitmq`). El admin aquí solo se usa para PUBLICAR en el
    // exchange `scan.outcomes`, algo que el usuario `gateway` no tiene
    // permitido (`write` solo sobre `scan.requests`/`scan.cancellations`) —
    // en producción quien publica ahí es `ms-nmap`, no este Gateway.
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
        .confirm_select(ConfirmSelectOptions::default())
        .await
        .expect("confirm_select del canal de administración");

    async fn publish(channel: &lapin::Channel, routing_key: &str, payload: &[u8]) {
        channel
            .basic_publish(
                "scan.outcomes",
                routing_key,
                BasicPublishOptions::default(),
                payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
            .expect("basic_publish debe enviarse")
            .await
            .expect("el Broker debe confirmar la publicación de prueba");
    }

    let started = json!({ "status": "started", "correlation_id": SCAN_ID }).to_string();
    publish(&admin_channel, "scan.outcome.started", started.as_bytes()).await;

    // Mensaje malformado de por medio: JSON inválido. Debe descartarse (log
    // + nack) sin tumbar el consumidor ni aparecer como evento SSE.
    publish(
        &admin_channel,
        "scan.outcome.completed",
        b"this is not valid json",
    )
    .await;

    let result = ScanResult {
        host: "192.0.2.10".to_string(),
        ports: vec![],
        vulnerabilities: vec![],
        scanned_at: "2024-01-01T00:00:00Z".to_string(),
    };
    let completed = serde_json::to_string(&json!({
        "status": "completed",
        "correlation_id": SCAN_ID,
        "result": result,
    }))
    .expect("debe serializar el evento completed de prueba");
    publish(
        &admin_channel,
        "scan.outcome.completed",
        completed.as_bytes(),
    )
    .await;

    let first = tokio::time::timeout(
        Duration::from_secs(15),
        next_sse_data_field(&mut byte_stream, &mut buffer),
    )
    .await
    .expect("no debe colgarse esperando el primer evento (started)")
    .expect("debe llegar el evento started");
    assert!(first.contains("\"status\":\"started\""));

    let second = tokio::time::timeout(
        Duration::from_secs(15),
        next_sse_data_field(&mut byte_stream, &mut buffer),
    )
    .await
    .expect("no debe colgarse esperando el segundo evento (completed, saltando el malformado)")
    .expect("debe llegar el evento completed");
    assert!(second.contains("\"status\":\"completed\""));

    let after_terminal = tokio::time::timeout(
        Duration::from_secs(5),
        next_sse_data_field(&mut byte_stream, &mut buffer),
    )
    .await
    .expect("el stream debe cerrarse (None), no colgarse, tras el evento terminal");
    assert!(
        after_terminal.is_none(),
        "el stream SSE debe cerrarse ordenadamente tras el evento terminal (completed)"
    );

    // Espera best-effort a que las llamadas a ms-usuarios (asíncronas,
    // disparadas por el mismo handler que relaya a SSE) se registren.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let captured = usuarios_calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        if captured.len() >= 2 || tokio::time::Instant::now() >= deadline {
            assert_eq!(
                captured,
                vec![
                    ("ms-usuarios-scan-1".to_string(), "EN_PROGRESO".to_string()),
                    ("ms-usuarios-scan-1".to_string(), "COMPLETADO".to_string()),
                ],
                "ms-usuarios debe recibir EN_PROGRESO y luego COMPLETADO para el scan_id correcto"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
