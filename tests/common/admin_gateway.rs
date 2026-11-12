//! Arnés compartido de los tests de las rutas de administración (feature
//! `admin_realtime_feed`): el router real de `gateway::api::app_router` con un
//! `ms-usuarios` stub cuyos roles por identidad puede cambiar el test (para
//! probar revocaciones) y un `events-service` falso ([`FakeEventsService`])
//! servido en proceso.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use gateway::admin::AdminFeed;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::{Role, Session};
use gateway::events_client::EventsClient;
use gateway::realtime::RealtimeRegistry;
use gateway::security_events::NoopSecurityEventPublisher;
use gateway::usuarios_client::{UsuariosClient, FORWARDED_USER_HEADER_NAME};
use jsonwebtoken::jwk::JwkSet;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const SHARED_SECRET: &str = "lab-only-usuarios-shared-secret";
/// Credencial de servicio que el gateway debe enviar a `events-service`.
pub const EVENTS_SECRET: &str = "lab-only-events-shared-secret";

pub struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("no debe publicar");
    }

    async fn publish_scan_cancellation(&self, _c: &ScanCancellation) -> Result<(), BrokerError> {
        panic!("no debe publicar");
    }
}

/// Estado del stub de `ms-usuarios`: rol vigente por `sub` y un fallo global
/// opcional.
#[derive(Clone, Default)]
pub struct UsuariosStub {
    pub roles: Arc<Mutex<HashMap<String, &'static str>>>,
    pub fail_with: Arc<Mutex<Option<StatusCode>>>,
}

async fn get_users_me(
    State(stub): State<UsuariosStub>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Some(status) = *stub.fail_with.lock().unwrap() {
        return (status, Json(json!({})));
    }
    let sub = headers
        .get(FORWARDED_USER_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|identity| identity["sub"].as_str().map(str::to_string));
    match sub.and_then(|sub| stub.roles.lock().unwrap().get(&sub).copied()) {
        Some(role) => (StatusCode::OK, Json(json!({ "role": role }))),
        None => (StatusCode::NOT_FOUND, Json(json!({}))),
    }
}

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor de prueba")
    });
    addr
}

async fn spawn_discovery_only_idp() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(issuer): State<String>| async move {
                Json(json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "jwks_uri": format!("{issuer}/jwks"),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }))
            }),
        )
        .route("/jwks", get(|| async { Json(JwkSet { keys: vec![] }) }))
        .with_state(issuer.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    issuer
}

pub struct Gateway {
    pub addr: SocketAddr,
    pub usuarios: UsuariosStub,
}

/// `events-service` falso, en proceso y vivo mientras el test lo conserve:
/// `GET /metrics` devuelve la respuesta configurada y `GET /events` entrega
/// los trozos que el test empuja con [`FakeEventsService::push`].
pub struct FakeEventsService {
    pub addr: SocketAddr,
    /// Peticiones recibidas (cualquier ruta).
    pub calls: Arc<AtomicUsize>,
    /// Último valor del header `X-Gateway-Secret` recibido.
    pub last_secret: Arc<Mutex<Option<String>>>,
    metrics: Arc<Mutex<(StatusCode, String)>>,
    sender: Mutex<Option<mpsc::UnboundedSender<Bytes>>>,
}

#[derive(Clone)]
struct FakeState {
    calls: Arc<AtomicUsize>,
    last_secret: Arc<Mutex<Option<String>>>,
    metrics: Arc<Mutex<(StatusCode, String)>>,
    receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<Bytes>>>>,
}

fn record(state: &FakeState, headers: &HeaderMap) {
    state.calls.fetch_add(1, Ordering::SeqCst);
    *state.last_secret.lock().unwrap() = headers
        .get("x-gateway-secret")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
}

async fn fake_metrics(State(state): State<FakeState>, headers: HeaderMap) -> Response {
    record(&state, &headers);
    let (status, body) = state.metrics.lock().unwrap().clone();
    (status, [("content-type", "application/json")], body).into_response()
}

async fn fake_events(State(state): State<FakeState>, headers: HeaderMap) -> Response {
    record(&state, &headers);
    let Some(mut rx) = state.receiver.lock().unwrap().take() else {
        return StatusCode::CONFLICT.into_response();
    };
    let stream = futures_util::stream::poll_fn(move |cx| {
        rx.poll_recv(cx)
            .map(|chunk| chunk.map(Ok::<Bytes, std::convert::Infallible>))
    });
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

impl FakeEventsService {
    pub async fn spawn() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = FakeState {
            calls: Arc::new(AtomicUsize::new(0)),
            last_secret: Arc::new(Mutex::new(None)),
            metrics: Arc::new(Mutex::new((StatusCode::OK, "{}".to_string()))),
            receiver: Arc::new(Mutex::new(Some(rx))),
        };
        Self {
            addr: serve(
                Router::new()
                    .route("/metrics", get(fake_metrics))
                    .route("/events", get(fake_events))
                    .with_state(state.clone()),
            )
            .await,
            calls: state.calls.clone(),
            last_secret: state.last_secret.clone(),
            metrics: state.metrics.clone(),
            sender: Mutex::new(Some(tx)),
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_metrics(&self, status: StatusCode, body: &str) {
        *self.metrics.lock().unwrap() = (status, body.to_string());
    }

    /// Empuja un trozo crudo al stream `GET /events` (puede cortar un frame).
    pub fn push(&self, chunk: &str) {
        self.sender
            .lock()
            .unwrap()
            .as_ref()
            .expect("el stream ya terminó")
            .send(Bytes::from(chunk.to_string()))
            .expect("el gateway cerró la conexión");
    }

    /// Termina el stream upstream (como un apagado de `events-service`).
    pub fn end(&self) {
        self.sender.lock().unwrap().take();
    }
}

/// Dirección en la que no escucha nadie (el puerto se liberó), para probar
/// un `events-service` inalcanzable.
pub async fn unreachable_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

/// Gateway completo (router real) cuyo `events-service` es `events_base_url`,
/// con `ms-usuarios` stub de roles por identidad.
pub async fn spawn_gateway(events_base_url: &str, role_recheck_interval: Duration) -> Gateway {
    let feed = Arc::new(AdminFeed::new(
        Arc::new(
            EventsClient::with_connect_timeout(
                events_base_url.to_string(),
                SecretString::from(EVENTS_SECRET.to_string()),
                Duration::from_millis(500),
            )
            .expect("cliente de events-service"),
        ),
        role_recheck_interval,
    ));
    let issuer = spawn_discovery_only_idp().await;
    let oidc = OidcClient::discover(
        &issuer,
        "test-client-id",
        &SecretString::from("test-client-secret".to_string()),
        "http://gateway.lab/auth/callback",
    )
    .await
    .expect("discovery");

    let usuarios_stub = UsuariosStub::default();
    let usuarios_addr = serve(
        Router::new()
            .route("/users/me", get(get_users_me))
            .with_state(usuarios_stub.clone()),
    )
    .await;
    let usuarios_client = UsuariosClient::new(
        format!("http://{usuarios_addr}"),
        SecretString::from(SHARED_SECRET.to_string()),
    )
    .expect("cliente")
    .with_role_check_timeout(Duration::from_secs(1));

    let state = AppState {
        oidc_client: Arc::new(oidc),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: SecretString::from(SESSION_SIGNING_KEY.to_string()),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        front_base_url: "https://front.lab".to_string(),
        front_origin: HeaderValue::from_static("https://front.lab"),
        usuarios_client: Arc::new(usuarios_client),
        broker_publisher: Arc::new(NeverPublishesToBroker),
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
        scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(
            1000,
            Duration::from_secs(60),
        )),
        security_events: Arc::new(NoopSecurityEventPublisher),
        admin_feed: feed,
    };
    let addr = serve(app_router(state)).await;
    Gateway {
        addr,
        usuarios: usuarios_stub,
    }
}

impl Gateway {
    /// Registra el rol vigente de `sub` en `ms-usuarios`.
    pub fn set_role(&self, sub: &str, role: &'static str) {
        self.usuarios
            .roles
            .lock()
            .unwrap()
            .insert(sub.to_string(), role);
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

pub fn cookie_for(sub: &str, claim: Role) -> String {
    let session = Session {
        sub: sub.to_string(),
        email: "someone@example.com".to_string(),
        name: "Someone".to_string(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        role: claim,
    };
    let token = issue_session_token(
        &session,
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("firma");
    format!("{SESSION_COOKIE_NAME}={token}")
}

pub async fn get_with(gw: &Gateway, path: &str, cookie: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(gw.url(path));
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    request.send().await.expect("la ruta debe responder")
}
