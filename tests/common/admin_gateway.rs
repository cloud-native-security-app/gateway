//! Arnés compartido de los tests de las rutas de administración (feature
//! `admin_realtime_feed`): el router real de `gateway::api::app_router` con un
//! `ms-usuarios` stub cuyos roles por identidad puede cambiar el test (para
//! probar revocaciones) y un agregador inyectable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use gateway::admin::{AdminAggregator, AdminFeed, ManualClock};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::{Role, Session};
use gateway::event_contract::parse_record;
use gateway::realtime::RealtimeRegistry;
use gateway::security_events::{NoopSecurityEventPublisher, SecurityEvent};
use gateway::usuarios_client::{UsuariosClient, FORWARDED_USER_HEADER_NAME};
use jsonwebtoken::jwk::JwkSet;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const SHARED_SECRET: &str = "lab-only-usuarios-shared-secret";

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
    pub feed: Arc<AdminFeed>,
    pub usuarios: UsuariosStub,
}

/// Gateway completo con un agregador de reloj manual vacío.
pub async fn spawn_gateway(role_recheck_interval: Duration) -> Gateway {
    let feed = Arc::new(AdminFeed::new(
        Arc::new(AdminAggregator::new(Arc::new(ManualClock::new(
            1_800_000_000_000,
        )))),
        role_recheck_interval,
    ));
    spawn_gateway_with_feed(feed).await
}

/// Gateway completo (router real) sobre el `feed` dado, con `ms-usuarios`
/// stub de roles por identidad.
pub async fn spawn_gateway_with_feed(feed: Arc<AdminFeed>) -> Gateway {
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
        admin_feed: feed.clone(),
    };
    let addr = serve(app_router(state)).await;
    Gateway {
        addr,
        feed,
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

pub fn event(
    n: u64,
    event_type: &str,
    actor: Option<&str>,
    scan: Option<&str>,
    payload: Value,
) -> SecurityEvent {
    let mut body = json!({
        "event_id": format!("00000000-0000-4000-8000-{n:012}"),
        "event_type": event_type,
        "occurred_at": "2026-11-10T12:00:00Z",
        "source": "gateway",
        "payload": payload,
    });
    if let Some(actor) = actor {
        body["actor_sub"] = json!(actor);
    }
    if let Some(scan) = scan {
        body["scan_id"] = json!(scan);
    }
    parse_record(&serde_json::to_vec(&body).unwrap()).expect("evento válido")
}
