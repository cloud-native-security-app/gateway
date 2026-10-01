//! Test de integración de la feature `scan_outcome_consumer_reconnect`.
//!
//! Reproduce el incidente confirmado en AWS: se fuerza el cierre de la
//! conexión AMQP subyacente de un [`BrokerConsumer`] que ya está corriendo
//! en segundo plano (mismo mecanismo que
//! `tests/broker_publisher_reconnect.rs`: Management HTTP API de
//! `rabbitmq:4.3.5-management`, `DELETE /api/connections/{name}` -- el
//! usuario `gateway` no tiene permiso `configure`, pero cerrar su propia
//! conexión desde afuera no lo necesita) y se confirma que el relay SSE
//! vuelve a funcionar para un escaneo posterior **sin reiniciar el proceso
//! de gateway** (misma tarea de fondo, lanzada una única vez con
//! `tokio::spawn`, de principio a fin de este test) -- mismo patrón de
//! `testcontainers` que `tests/scan_outcome_relay.rs`/
//! `tests/broker_publisher_reconnect.rs` (ver `docs/verification.md` Nivel
//! 3).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Path as AxumPath;
use axum::http::HeaderValue;
use axum::routing::patch;
use axum::{Json, Router};
use futures_util::StreamExt;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{
    BrokerConsumer, BrokerError, ScanCancellation, ScanOutcomeHandler, ScanRequest,
    ScanRequestPublisher,
};
use gateway::domain::{ScanOutcomeEvent, Session};
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::UsuariosClient;
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

/// Credenciales de laboratorio del usuario RabbitMQ `gateway`, copiadas de
/// `broker/rabbitmq/README.md` -- mismo usuario con permiso `read` solo
/// sobre `gateway.scan-outcomes`.
const GATEWAY_RABBITMQ_USER: &str = "gateway";
const GATEWAY_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret-gateway";

/// Credenciales de laboratorio del usuario administrador de RabbitMQ, único
/// con permiso para usar la Management HTTP API y para publicar en
/// `scan.outcomes` (en producción, quien publica ahí es `ms-nmap`, no este
/// Gateway).
const ADMIN_RABBITMQ_USER: &str = "lab-admin";
const ADMIN_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret";

/// Doble de prueba de [`ScanRequestPublisher`]: este test no ejerce `POST
/// /api/scans`.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("este test no debe llegar a publicar en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este test no debe llegar a publicar una cancelación en el Broker");
    }
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

async fn spawn_discovery_only_idp() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del IdP de prueba");
    let addr = listener.local_addr().expect("addr del IdP de prueba");
    let issuer_url = format!("http://{addr}");

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(serve_discovery),
        )
        .route("/jwks", axum::routing::get(serve_empty_jwks))
        .with_state(issuer_url.clone());

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del IdP de prueba");
    });

    issuer_url
}

/// Responde siempre 204, sin capturar nada -- este test solo verifica el
/// relay SSE antes/después de reconectar, no el best-effort hacia
/// `ms-usuarios` (ya cubierto por `tests/scan_outcome_relay.rs`).
async fn serve_patch_scan_status(AxumPath(_scan_id): AxumPath<String>) -> axum::http::StatusCode {
    axum::http::StatusCode::NO_CONTENT
}

async fn spawn_usuarios_status_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new().route("/scans/:scan_id", patch(serve_patch_scan_status));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
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
        front_base_url: "https://front.lab".to_string(),
        front_origin: HeaderValue::from_static("https://front.lab"),
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

/// Puente entre [`BrokerConsumer`] y el resto del Gateway bajo prueba: igual
/// lógica que `gateway::wiring::ScanOutcomeRelay` (privada a ese módulo),
/// reconstruida aquí con la API pública para ejercer el mismo camino que
/// corre en producción (mismo patrón que `tests/scan_outcome_relay.rs`).
struct TestRelayHandler {
    scan_ownership: Arc<ScanOwnershipRegistry>,
    realtime: Arc<RealtimeRegistry>,
}

#[async_trait::async_trait]
impl ScanOutcomeHandler for TestRelayHandler {
    async fn handle(&self, event: ScanOutcomeEvent) {
        self.realtime.publish(&event);
        // Solo se verifica el registro de propiedad (igual que la lógica
        // real) -- este test no verifica el best-effort hacia `ms-usuarios`,
        // ya cubierto por `tests/scan_outcome_relay.rs`.
        let _ = self.scan_ownership.lookup(event.correlation_id());
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
/// topología copiada literalmente de `broker/rabbitmq/definitions.json` (ver
/// `docs/architecture.md`) y el puerto de la Management HTTP API (15672)
/// publicado -- usado por este test para forzar el cierre de la conexión
/// AMQP del consumidor bajo prueba.
async fn start_rabbitmq() -> ContainerAsync<GenericImage> {
    install_crypto_provider_once();

    GenericImage::new("rabbitmq", "4.3.5-management")
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

/// Busca, vía la Management HTTP API, el nombre de **alguna** conexión AMQP
/// abierta por el usuario `gateway` contra `VHOST`, si `exclude` no es
/// `None` ignora una conexión con ese nombre exacto (usado por
/// [`wait_for_gateway_reconnect`] para esperar a que aparezca una conexión
/// *nueva*, distinta de la que se cerró).
async fn find_gateway_connection_name(
    http: &reqwest::Client,
    host: &str,
    management_port: u16,
    exclude: Option<&str>,
) -> Option<String> {
    let connections: Vec<Value> = http
        .get(format!("http://{host}:{management_port}/api/connections"))
        .basic_auth(ADMIN_RABBITMQ_USER, Some(ADMIN_RABBITMQ_PASSWORD))
        .send()
        .await
        .expect("la Management HTTP API debe responder a GET /api/connections")
        .json()
        .await
        .expect("la respuesta de /api/connections debe ser JSON válido");

    connections
        .iter()
        .find(|connection| {
            connection["user"] == Value::String(GATEWAY_RABBITMQ_USER.to_string())
                && connection["vhost"] == Value::String(VHOST.to_string())
                && connection["name"].as_str() != exclude
        })
        .and_then(|connection| connection["name"].as_str())
        .map(str::to_string)
}

/// Busca la conexión AMQP abierta por el usuario `gateway` contra `VHOST` y
/// la cierra forzosamente -- mismo mecanismo que
/// `tests/broker_publisher_reconnect.rs` para reproducir "el Broker le
/// cerró la conexión a `gateway`" sin reiniciar el contenedor entero.
/// Devuelve el nombre de la conexión cerrada (para que
/// [`wait_for_gateway_reconnect`] pueda esperar a que aparezca una distinta).
async fn force_close_gateway_connection(
    http: &reqwest::Client,
    host: &str,
    management_port: u16,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    let connection_name = loop {
        if let Some(name) = find_gateway_connection_name(http, host, management_port, None).await {
            break name;
        }

        assert!(
            Instant::now() < deadline,
            "la Management HTTP API nunca listó la conexión del usuario gateway"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let mut delete_url =
        url::Url::parse(&format!("http://{host}:{management_port}/api/connections"))
            .expect("URL base de la Management HTTP API debe parsear");
    delete_url
        .path_segments_mut()
        .expect("la URL base debe admitir segmentos de path")
        .push(&connection_name);

    let response = http
        .delete(delete_url)
        .basic_auth(ADMIN_RABBITMQ_USER, Some(ADMIN_RABBITMQ_PASSWORD))
        .send()
        .await
        .expect("DELETE /api/connections/{name} debe responder");

    assert!(
        response.status().is_success(),
        "cerrar la conexión del usuario gateway debe responder 2xx, fue {}",
        response.status()
    );

    connection_name
}

/// Sondea la Management HTTP API hasta que aparece una conexión del usuario
/// `gateway` **distinta** de `closed_connection_name` -- confirmación
/// determinista de que [`BrokerConsumer::run`] ya reconectó, en vez de
/// asumir un tiempo fijo de espera o republicar a ciegas.
async fn wait_for_gateway_reconnect(
    http: &reqwest::Client,
    host: &str,
    management_port: u16,
    closed_connection_name: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if find_gateway_connection_name(http, host, management_port, Some(closed_connection_name))
            .await
            .is_some()
        {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "el consumidor nunca abrió una nueva conexión AMQP tras la caída (reconexión \
             esperada, ver BrokerConsumer::run)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

async fn publish_started(channel: &lapin::Channel, scan_id: &str) {
    let payload = json!({ "status": "started", "correlation_id": scan_id }).to_string();
    channel
        .basic_publish(
            "scan.outcomes",
            "scan.outcome.started",
            BasicPublishOptions::default(),
            payload.as_bytes(),
            BasicProperties::default().with_content_type("application/json".into()),
        )
        .await
        .expect("basic_publish debe enviarse")
        .await
        .expect("el Broker debe confirmar la publicación de prueba");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn consumer_reconnects_and_relays_sse_events_of_a_later_scan_without_restarting_the_process()
{
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
    let management_port = container
        .get_host_port_ipv4(15672.tcp())
        .await
        .expect("puerto de la Management HTTP API publicado del contenedor de prueba");

    let ca_pem = std::fs::read_to_string(fixture_path("rabbitmq/tls/ca_certificate.pem"))
        .expect("debe poder leer la CA de laboratorio");

    let usuarios_base_url = spawn_usuarios_status_stub().await;
    let gateway = spawn_gateway(lab_usuarios_client(usuarios_base_url)).await;

    // El consumidor bajo prueba: misma instancia/tarea de principio a fin de
    // este test -- nunca se reinicia ningún proceso, solo se cierra su
    // conexión AMQP subyacente desde afuera.
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
        scan_ownership: gateway.scan_ownership.clone(),
        realtime: gateway.realtime.clone(),
    });
    tokio::spawn(scan_outcome_consumer.run(handler));

    // Conexión de administración: único usuario con permiso para publicar en
    // el exchange `scan.outcomes` (en producción, quien publica ahí es
    // `ms-nmap`, no este Gateway).
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

    let http = http_client();

    // --- Antes de la caída: sanity check de que el relay funciona igual que
    // siempre mientras la conexión está sana (criterio de aceptación 3).
    const SCAN_ID_BEFORE: &str = "scan-reconnect-before";
    gateway.scan_ownership.register(
        SCAN_ID_BEFORE,
        "ms-usuarios-scan-before".to_string(),
        session_for("alice"),
    );

    let response_before = http
        .get(format!(
            "http://{}/api/scans/{SCAN_ID_BEFORE}/events",
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
    assert_eq!(response_before.status(), reqwest::StatusCode::OK);

    let mut byte_stream_before = response_before.bytes_stream();
    let mut buffer_before = String::new();

    publish_started(&admin_channel, SCAN_ID_BEFORE).await;

    let before_event = tokio::time::timeout(
        Duration::from_secs(15),
        next_sse_data_field(&mut byte_stream_before, &mut buffer_before),
    )
    .await
    .expect("no debe colgarse esperando el evento previo a la caída")
    .expect("debe llegar el evento started previo a la caída");
    assert!(before_event.contains("\"status\":\"started\""));
    drop(byte_stream_before);

    // --- Se fuerza el cierre de la conexión AMQP del consumidor -- igual
    // reproducción del incidente que `tests/broker_publisher_reconnect.rs`,
    // del lado del consumidor.
    let closed_connection_name =
        force_close_gateway_connection(&http, &host, management_port).await;

    // Confirmación determinista de que `BrokerConsumer::run` ya reconectó
    // (nueva conexión AMQP abierta) antes de publicar el siguiente evento --
    // en vez de asumir un tiempo fijo o republicar a ciegas.
    wait_for_gateway_reconnect(&http, &host, management_port, &closed_connection_name).await;

    // --- Después de la caída: un escaneo posterior debe seguir relayándose
    // por SSE, sin reiniciar el proceso de gateway (criterio de aceptación
    // 1/2/5).
    const SCAN_ID_AFTER: &str = "scan-reconnect-after";
    gateway.scan_ownership.register(
        SCAN_ID_AFTER,
        "ms-usuarios-scan-after".to_string(),
        session_for("alice"),
    );

    let response_after = http
        .get(format!(
            "http://{}/api/scans/{SCAN_ID_AFTER}/events",
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
        .expect("la conexión SSE posterior a la caída debe aceptarse");
    assert_eq!(response_after.status(), reqwest::StatusCode::OK);

    let mut byte_stream_after = response_after.bytes_stream();
    let mut buffer_after = String::new();

    publish_started(&admin_channel, SCAN_ID_AFTER).await;

    let after_event = tokio::time::timeout(
        Duration::from_secs(15),
        next_sse_data_field(&mut byte_stream_after, &mut buffer_after),
    )
    .await
    .expect("no debe colgarse esperando el evento posterior a la reconexión")
    .expect("debe llegar el evento started posterior a la reconexión, sin reiniciar el proceso");
    assert!(after_event.contains("\"status\":\"started\""));
}
