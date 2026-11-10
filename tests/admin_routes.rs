//! Tests de integración de las rutas de administración (feature
//! `admin_realtime_feed`, tarea KAP-09): `GET /api/admin/metrics` y el SSE
//! `GET /api/admin/events`, servidas por el router real de
//! `gateway::api::app_router` detrás de `require_session` + `require_admin`.
//! `ms-usuarios` es un stub local con roles por identidad que el test puede
//! cambiar (para probar la revocación durante un stream abierto) y el
//! agregador usa un reloj manual. No requieren Docker.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
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
const RECHECK: Duration = Duration::from_millis(250);
const WAIT: Duration = Duration::from_secs(5);

struct NeverPublishesToBroker;

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
struct UsuariosStub {
    roles: Arc<Mutex<HashMap<String, &'static str>>>,
    fail_with: Arc<Mutex<Option<StatusCode>>>,
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

struct Gateway {
    addr: SocketAddr,
    feed: Arc<AdminFeed>,
    usuarios: UsuariosStub,
}

async fn spawn_gateway(role_recheck_interval: Duration) -> Gateway {
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

    let feed = Arc::new(AdminFeed::new(
        Arc::new(AdminAggregator::new(Arc::new(ManualClock::new(
            1_800_000_000_000,
        )))),
        role_recheck_interval,
    ));
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
    fn set_role(&self, sub: &str, role: &'static str) {
        self.usuarios
            .roles
            .lock()
            .unwrap()
            .insert(sub.to_string(), role);
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

fn cookie_for(sub: &str, claim: Role) -> String {
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

async fn get_with(gw: &Gateway, path: &str, cookie: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(gw.url(path));
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    request.send().await.expect("la ruta debe responder")
}

fn event(
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

/// Lector mínimo de `text/event-stream`: devuelve `(evento, datos)`, ignorando
/// los comentarios de keep-alive.
struct SseReader {
    stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    buffer: String,
}

impl SseReader {
    async fn open(gw: &Gateway, cookie: &str) -> Self {
        let response = get_with(gw, "/api/admin/events", Some(cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        Self {
            stream: Box::pin(response.bytes_stream()),
            buffer: String::new(),
        }
    }

    /// Siguiente evento, o `None` si el stream terminó.
    async fn next(&mut self) -> Option<(String, Value)> {
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                let mut name = None;
                let mut data = String::new();
                for line in block.lines() {
                    if let Some(rest) = line.strip_prefix("event:") {
                        name = Some(rest.trim().to_string());
                    } else if let Some(rest) = line.strip_prefix("data:") {
                        data.push_str(rest.trim());
                    }
                }
                if let Some(name) = name {
                    return Some((name, serde_json::from_str(&data).unwrap_or(Value::Null)));
                }
                continue; // solo comentario (keep-alive)
            }
            let chunk = tokio::time::timeout(WAIT, self.stream.next())
                .await
                .expect("el stream no debe quedarse mudo")?;
            self.buffer
                .push_str(&String::from_utf8_lossy(&chunk.expect("chunk")));
        }
    }

    async fn expect(&mut self, name: &str) -> Value {
        let (got, data) = self.next().await.expect("el stream no debe terminar aún");
        assert_eq!(got, name, "datos: {data}");
        data
    }
}

#[tokio::test]
async fn admin_routes_without_a_session_get_401() {
    let gw = spawn_gateway(RECHECK).await;
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, None).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
}

#[tokio::test]
async fn non_admin_gets_403_on_every_admin_route() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("plain-user", "user");
    let cookie = cookie_for("plain-user", Role::User);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response.text().await.unwrap(), "acceso denegado");
    }
}

#[tokio::test]
async fn demoted_admin_with_a_stale_admin_cookie_gets_403() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("ex-admin", "user");
    let cookie = cookie_for("ex-admin", Role::Admin);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn unverifiable_role_gets_503() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::INTERNAL_SERVER_ERROR);
    let response = get_with(
        &gw,
        "/api/admin/metrics",
        Some(&cookie_for("admin-1", Role::Admin)),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn admin_gets_the_metrics_snapshot_as_json() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    gw.feed
        .aggregator
        .ingest(&event(1, "auth.login", Some("someone"), None, json!({})));
    gw.feed
        .aggregator
        .ingest(&event(2, "scan.started", None, Some("scan-1"), json!({})));
    gw.feed.aggregator.record_malformed();

    let response = get_with(
        &gw,
        "/api/admin/metrics",
        Some(&cookie_for("admin-1", Role::Admin)),
    )
    .await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["kpis"]["scans_in_flight"], 1);
    assert_eq!(body["kpis"]["active_users"], 1);
    assert_eq!(body["kpis"]["malformed_records"], 1);
    assert_eq!(body["scans_in_flight"][0]["scan_id"], "scan-1");
    assert_eq!(body["scans_in_flight"][0]["status"], "running");
    assert_eq!(body["recent_events"][0]["event_type"], "scan.started");
    assert_eq!(body["window_seconds"], 900);
    assert!(
        !body.to_string().contains("example.com"),
        "el snapshot no contiene correos ni nombres"
    );
}

#[tokio::test]
async fn sse_sends_a_snapshot_first_then_a_delta_for_each_new_event() {
    let gw = spawn_gateway(Duration::from_secs(60)).await;
    gw.set_role("admin-1", "admin");
    gw.feed
        .aggregator
        .ingest(&event(1, "auth.login", Some("early"), None, json!({})));
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;

    let snapshot = sse.expect("snapshot").await;
    assert_eq!(snapshot["kpis"]["active_users"], 1);
    assert_eq!(snapshot["seq"], 1);

    gw.feed.aggregator.ingest(&event(
        2,
        "scan.requested",
        Some("u"),
        Some("scan-9"),
        json!({"target": "198.51.100.4"}),
    ));
    let delta = sse.expect("delta").await;
    assert_eq!(delta["seq"], 2);
    assert_eq!(delta["event"]["event_type"], "scan.requested");
    assert_eq!(
        delta["scan_change"],
        json!({"scan_id": "scan-9", "status": "requested"})
    );
    assert_eq!(delta["kpis"]["scans_in_flight"], 1);
}

#[tokio::test]
async fn sse_refreshes_the_snapshot_on_every_role_revalidation_while_the_admin_stays_admin() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    // Sin eventos de por medio, el siguiente mensaje es el snapshot de la
    // revalidación (la ventana de los KPIs vence sin que llegue ningún evento).
    sse.expect("snapshot").await;
    sse.expect("snapshot").await;
}

#[tokio::test]
async fn sse_closes_after_the_role_is_revoked_on_revalidation() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    gw.set_role("admin-1", "user");

    let closed = loop {
        let (name, data) = sse
            .next()
            .await
            .expect("debe llegar `closed` antes del fin");
        if name == "closed" {
            break data;
        }
        assert_eq!(
            name, "snapshot",
            "solo snapshots de revalidación antes de revocar"
        );
    };
    assert_eq!(closed, json!({"reason": "role_revalidation_failed"}));
    assert!(
        sse.next().await.is_none(),
        "el stream debe terminar tras `closed`"
    );
}

#[tokio::test]
async fn sse_closes_when_the_role_cannot_be_verified() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::BAD_GATEWAY);

    loop {
        let (name, _) = sse.next().await.expect("debe cerrarse con `closed`");
        if name == "closed" {
            break;
        }
    }
    assert!(sse.next().await.is_none());
}

#[tokio::test]
async fn sse_closes_when_the_user_disappears_from_ms_usuarios() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    gw.usuarios.roles.lock().unwrap().remove("admin-1");

    loop {
        let (name, _) = sse.next().await.expect("debe cerrarse con `closed`");
        if name == "closed" {
            break;
        }
    }
    assert!(sse.next().await.is_none());
}
