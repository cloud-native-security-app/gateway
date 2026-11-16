//! Tests de integración de la feature `network_scan_mode` (NS-03):
//! `POST /api/scans` con `mode: "network"`.
//!
//! Mismo patrón que `tests/scan_submission.rs`: el router real de
//! `gateway::api::app_router` sobre un puerto efímero, con un stub HTTP real
//! de `ms-usuarios` y un doble de [`ScanRequestPublisher`] que graba el
//! payload publicado. El payload se valida contra el schema del Broker
//! (`../broker/contracts/scan-request.schema.json`); si el checkout hermano
//! no existe, esas validaciones se omiten con aviso (igual que
//! `tests/security_event_contract.rs`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use gateway::admin::AdminFeed;
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::{Role, Session};
use gateway::network_scan::NetworkScanPolicy;
use gateway::realtime::RealtimeRegistry;
use gateway::security_events::{
    NoopSecurityEventPublisher, RecordingSecurityEventPublisher, SecurityEventPublisher,
};
use gateway::usuarios_client::UsuariosClient;
use jsonschema::Validator;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const SHARED_SECRET: &str = "lab-only-not-a-real-secret";

// --- Dobles -----------------------------------------------------------------

/// Graba el JSON exacto de cada `ScanRequest` publicado.
#[derive(Default, Clone)]
struct RecordingPublisher {
    published: Arc<Mutex<Vec<Value>>>,
}

#[async_trait::async_trait]
impl ScanRequestPublisher for RecordingPublisher {
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError> {
        self.published
            .lock()
            .expect("lock")
            .push(serde_json::to_value(request).expect("serializa"));
        Ok(())
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("este escenario no cancela");
    }
}

/// Stub de `ms-usuarios`: perfil configurable, y registro de cada llamada.
#[derive(Clone)]
struct UsuariosStub {
    profile_status: Arc<AtomicU16>,
    profile_body: Arc<Mutex<Value>>,
    calls: Arc<Mutex<Vec<String>>>,
    history: Arc<Mutex<Vec<Value>>>,
    /// Cuerpos exactos recibidos en `POST /users/me/scans`.
    create_bodies: Arc<Mutex<Vec<Value>>>,
    /// Simula un `ms-usuarios` anterior que no devuelve `scan_mode`.
    legacy_history: Arc<std::sync::atomic::AtomicBool>,
}

impl UsuariosStub {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock").clone()
    }

    fn count(&self, prefix: &str) -> usize {
        self.calls()
            .iter()
            .filter(|c| c.starts_with(prefix))
            .count()
    }

    fn set_profile(&self, status: u16, body: Value) {
        self.profile_status.store(status, Ordering::SeqCst);
        *self.profile_body.lock().expect("lock") = body;
    }
}

async fn spawn_usuarios_stub(profile_body: Value) -> (String, UsuariosStub) {
    let stub = UsuariosStub {
        profile_status: Arc::new(AtomicU16::new(200)),
        profile_body: Arc::new(Mutex::new(profile_body)),
        calls: Arc::default(),
        history: Arc::default(),
        create_bodies: Arc::default(),
        legacy_history: Arc::default(),
    };

    async fn profile(State(s): State<UsuariosStub>) -> (StatusCode, Json<Value>) {
        s.calls.lock().expect("lock").push("profile".into());
        let status = StatusCode::from_u16(s.profile_status.load(Ordering::SeqCst)).unwrap();
        (status, Json(s.profile_body.lock().expect("lock").clone()))
    }
    async fn resolve(State(s): State<UsuariosStub>) -> Json<Value> {
        s.calls.lock().expect("lock").push("resolve".into());
        Json(json!({
            "network_user": "netuser-lab",
            "ssh_credentials_ref": "lab-only-not-a-real-secret",
            "has_sudo": true,
        }))
    }
    async fn create_history(State(s): State<UsuariosStub>, Json(body): Json<Value>) -> Json<Value> {
        let target = body["target"].as_str().unwrap_or_default().to_string();
        s.create_bodies.lock().expect("lock").push(body.clone());
        s.calls
            .lock()
            .expect("lock")
            .push(format!("history:{target}"));
        let mut history = s.history.lock().expect("lock");
        let entry = json!({
            "scan_id": format!("ms-usuarios-history-{}", history.len() + 1),
            "user_id": "google-sub-123",
            "target": target,
            "status": "PENDIENTE",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "failure_reason": null,
        });
        let mut entry = entry;
        if !s.legacy_history.load(Ordering::SeqCst) {
            // Como el `user-service` real: persiste `scan_mode`, `ssh` por defecto.
            entry["scan_mode"] = body.get("scan_mode").cloned().unwrap_or(json!("ssh"));
        }
        history.push(entry.clone());
        Json(entry)
    }
    async fn list_history(State(s): State<UsuariosStub>) -> Json<Value> {
        Json(Value::Array(s.history.lock().expect("lock").clone()))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("addr stub");
    let app = Router::new()
        .route("/users/me", get(profile))
        .route("/users/me/scan-targets", get(resolve))
        .route("/users/me/scans", post(create_history).get(list_history))
        .with_state(stub.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub ms-usuarios");
    });
    (format!("http://{addr}"), stub)
}

async fn spawn_discovery_only_idp() -> String {
    async fn discovery(State(issuer_url): State<String>) -> Json<Value> {
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
    async fn jwks() -> Json<jsonwebtoken::jwk::JwkSet> {
        Json(jsonwebtoken::jwk::JwkSet { keys: vec![] })
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind idp");
    let addr = listener.local_addr().expect("addr idp");
    let issuer_url = format!("http://{addr}");
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .with_state(issuer_url.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("idp");
    });
    issuer_url
}

// --- Harness ----------------------------------------------------------------

struct GatewayUnderTest {
    addr: std::net::SocketAddr,
}

struct Options {
    policy: NetworkScanPolicy,
    rate_limit: u32,
    events: Arc<dyn SecurityEventPublisher>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: NetworkScanPolicy::unrestricted(),
            rate_limit: 1000,
            events: Arc::new(NoopSecurityEventPublisher),
        }
    }
}

async fn spawn_gateway(
    usuarios_base_url: String,
    publisher: Arc<dyn ScanRequestPublisher>,
    options: Options,
) -> GatewayUnderTest {
    let issuer_url = spawn_discovery_only_idp().await;
    let oidc_client = OidcClient::discover(
        &issuer_url,
        "test-client-id",
        &SecretString::from("test-client-secret".to_string()),
        "http://gateway.lab/auth/callback",
    )
    .await
    .expect("discovery");
    let usuarios_client = UsuariosClient::new(
        usuarios_base_url,
        SecretString::from(SHARED_SECRET.to_string()),
    )
    .expect("cliente");

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
        broker_publisher: publisher,
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
        scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(
            options.rate_limit,
            Duration::from_secs(60),
        )),
        security_events: options.events,
        admin_feed: Arc::new(AdminFeed::default()),
        network_scan_policy: Arc::new(options.policy),
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("addr gateway");
    let app = app_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway");
    });
    GatewayUnderTest { addr }
}

/// Gateway + stub + publicador grabador, con el usuario dado.
struct Harness {
    gateway: GatewayUnderTest,
    stub: UsuariosStub,
    published: Arc<Mutex<Vec<Value>>>,
}

async fn harness_with(profile: Value, options: Options) -> Harness {
    let (url, stub) = spawn_usuarios_stub(profile).await;
    let publisher = RecordingPublisher::default();
    let published = publisher.published.clone();
    let gateway = spawn_gateway(url, Arc::new(publisher), options).await;
    Harness {
        gateway,
        stub,
        published,
    }
}

async fn harness(can_network_scan: bool) -> Harness {
    harness_with(
        json!({"role": "user", "can_network_scan": can_network_scan}),
        Options::default(),
    )
    .await
}

fn cookie() -> String {
    let session = Session {
        sub: "google-sub-123".to_string(),
        email: "user@example.com".to_string(),
        name: "Test User".to_string(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        role: Role::User,
    };
    let token = issue_session_token(
        &session,
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("sesión");
    format!("{SESSION_COOKIE_NAME}={token}")
}

impl Harness {
    async fn post(&self, body: Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("http://{}/api/scans", self.gateway.addr))
            .header(reqwest::header::COOKIE, cookie())
            .json(&body)
            .send()
            .await
            .expect("POST /api/scans")
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("http://{}{path}", self.gateway.addr))
            .header(reqwest::header::COOKIE, cookie())
            .send()
            .await
            .expect("GET")
    }

    fn published(&self) -> Vec<Value> {
        self.published.lock().expect("lock").clone()
    }

    fn assert_nothing_happened(&self) {
        assert!(self.published().is_empty(), "no debe publicarse nada");
        assert_eq!(self.stub.count("resolve"), 0, "sin resolver credenciales");
        assert_eq!(self.stub.count("history"), 0, "sin registrar histórico");
    }
}

fn network(target: &str) -> Value {
    json!({"target": target, "mode": "network"})
}

// --- Contrato del Broker ----------------------------------------------------

fn broker_schema(name: &str) -> Option<Validator> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(name);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("schema JSON");
    Some(jsonschema::validator_for(&schema).expect("schema compila"))
}

// --- Permiso ----------------------------------------------------------------

#[tokio::test]
async fn permitted_user_publishes_a_network_request_that_validates_against_the_broker_schema() {
    let h = harness(true).await;

    let response = h.post(network("192.0.2.10")).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("json");
    let published = h.published();
    assert_eq!(published.len(), 1);
    assert_eq!(
        published[0],
        json!({
            "correlation_id": body["scanId"],
            "scan_mode": "network",
            "ip": "192.0.2.10",
            "requested_by": "google-sub-123",
        })
    );
    if let Some(validator) = broker_schema("scan-request.schema.json") {
        let errors: Vec<_> = validator
            .iter_errors(&published[0])
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "no valida contra el contrato: {errors:?}"
        );
    }
    assert_eq!(
        h.stub.count("resolve"),
        0,
        "network no resuelve credenciales SSH"
    );
    assert_eq!(
        h.stub.count("history:192.0.2.10"),
        1,
        "el histórico sí se registra"
    );
}

#[tokio::test]
async fn user_without_the_permission_gets_403_and_nothing_happens() {
    for profile in [
        json!({"role": "user", "can_network_scan": false}),
        json!({"role": "user"}),
        // Ser admin no concede el permiso.
        json!({"role": "admin"}),
    ] {
        let h = harness_with(profile.clone(), Options::default()).await;

        let response = h.post(network("192.0.2.10")).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{profile}");
        let body: Value = response.json().await.expect("json");
        assert_eq!(body["error"], "network_scan_not_permitted");
        h.assert_nothing_happened();
    }
}

#[tokio::test]
async fn user_service_404_denies_with_403() {
    let h = harness(true).await;
    h.stub.set_profile(404, json!({}));

    let response = h.post(network("192.0.2.10")).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    h.assert_nothing_happened();
}

#[tokio::test]
async fn user_service_failures_fail_closed_with_503() {
    for status in [500, 502, 401] {
        let h = harness(true).await;
        h.stub.set_profile(status, json!({"error": "x"}));

        let response = h.post(network("192.0.2.10")).await;

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "status {status}"
        );
        let body: Value = response.json().await.expect("json");
        assert_eq!(body["error"], "network_scan_permission_unavailable");
        h.assert_nothing_happened();
    }
}

#[tokio::test]
async fn unreachable_user_service_fails_closed_with_503() {
    let publisher = RecordingPublisher::default();
    let published = publisher.published.clone();
    let gateway = spawn_gateway(
        "http://127.0.0.1:1".to_string(),
        Arc::new(publisher),
        Options::default(),
    )
    .await;

    let response = reqwest::Client::new()
        .post(format!("http://{}/api/scans", gateway.addr))
        .header(reqwest::header::COOKIE, cookie())
        .json(&network("192.0.2.10"))
        .send()
        .await
        .expect("POST");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(published.lock().unwrap().is_empty());
}

#[tokio::test]
async fn permission_is_revalidated_on_every_request() {
    let h = harness(true).await;
    assert_eq!(h.post(network("192.0.2.10")).await.status(), StatusCode::OK);

    h.stub
        .set_profile(200, json!({"role": "user", "can_network_scan": false}));
    assert_eq!(
        h.post(network("192.0.2.11")).await.status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        h.stub.count("profile"),
        2,
        "una consulta por solicitud, sin caché"
    );
    assert_eq!(h.published().len(), 1);
}

#[tokio::test]
async fn permission_is_checked_before_any_other_network_mode_work() {
    // Sin permiso, un objetivo inválido, prohibido o fuera de rango recibe 403
    // (no 400/422): no se filtra nada sobre la política a quien no la puede usar.
    let h = harness_with(
        json!({"role": "user", "can_network_scan": false}),
        Options {
            policy: NetworkScanPolicy::new(vec!["10.0.0.0/24".parse().unwrap()]),
            ..Options::default()
        },
    )
    .await;

    for target in ["not-an-ip", "127.0.0.1", "192.0.2.10", "10.0.0.0/24"] {
        let response = h.post(network(target)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{target}");
    }
    h.assert_nothing_happened();
}

// --- Objetivos --------------------------------------------------------------

#[tokio::test]
async fn denylisted_targets_get_422_with_a_reason_code_and_nothing_is_published() {
    let cases = [
        ("127.0.0.1", "target_loopback"),
        ("::1", "target_loopback"),
        ("169.254.169.254", "target_link_local"),
        ("fe80::1", "target_link_local"),
        ("224.0.0.1", "target_multicast"),
        ("ff02::1", "target_multicast"),
        ("255.255.255.255", "target_broadcast"),
        ("0.0.0.0", "target_unspecified"),
        ("::", "target_unspecified"),
        ("::ffff:127.0.0.1", "target_loopback"),
        ("::ffff:169.254.169.254", "target_link_local"),
        ("::127.0.0.1", "target_loopback"),
        ("fd00:ec2::254", "target_unique_local"),
        // Un /32 normalizado a IP simple sigue sujeto a la lista.
        ("127.0.0.1/32", "target_loopback"),
    ];
    let h = harness(true).await;
    for (target, reason) in cases {
        let response = h.post(network(target)).await;

        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{target}"
        );
        let body: Value = response.json().await.expect("json");
        assert_eq!(body["error"], "network_scan_target_rejected", "{target}");
        assert_eq!(body["reason"], reason, "{target}");
    }
    assert!(h.published().is_empty());
    assert_eq!(h.stub.count("history"), 0);
}

#[tokio::test]
async fn malformed_network_target_is_still_a_400() {
    let h = harness(true).await;
    for target in ["not-an-ip", "10.0.0.0/24", ""] {
        let response = h.post(network(target)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target:?}");
    }
    assert!(h.published().is_empty());
}

#[tokio::test]
async fn allowlist_accepts_targets_inside_and_rejects_outside() {
    let h = harness_with(
        json!({"role": "user", "can_network_scan": true}),
        Options {
            policy: NetworkScanPolicy::new(vec!["10.0.0.0/24".parse().unwrap()]),
            ..Options::default()
        },
    )
    .await;

    assert_eq!(h.post(network("10.0.0.7")).await.status(), StatusCode::OK);
    // IPv4 envuelto en IPv6 dentro del rango: se publica la forma canónica.
    assert_eq!(
        h.post(network("::ffff:10.0.0.8")).await.status(),
        StatusCode::OK
    );
    // IPv4-compatible (obsoleto): misma canonicalización.
    assert_eq!(h.post(network("::10.0.0.9")).await.status(), StatusCode::OK);
    let published = h.published();
    assert_eq!(published[1]["ip"], "10.0.0.8");
    assert_eq!(published[2]["ip"], "10.0.0.9");

    let outside = h.post(network("192.0.2.10")).await;
    assert_eq!(outside.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = outside.json().await.expect("json");
    assert_eq!(body["reason"], "target_outside_allowed_ranges");
    assert_eq!(h.published().len(), 3, "el rechazado no se publica");
}

#[tokio::test]
async fn unset_allowlist_accepts_any_target_after_the_denylist() {
    let h = harness(true).await;
    assert_eq!(
        h.post(network("203.0.113.9")).await.status(),
        StatusCode::OK
    );
    assert_eq!(h.post(network("10.9.9.9")).await.status(), StatusCode::OK);
}

// --- ssh sin cambios --------------------------------------------------------

#[tokio::test]
async fn ssh_payload_is_unchanged_with_or_without_the_mode_field() {
    for body in [
        json!({"target": "192.0.2.10"}),
        json!({"target": "192.0.2.10", "mode": "ssh"}),
    ] {
        let h = harness(false).await;

        let response = h.post(body.clone()).await;

        assert_eq!(response.status(), StatusCode::OK, "{body}");
        let scan_id = response.json::<Value>().await.expect("json")["scanId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            h.published(),
            vec![json!({
                "correlation_id": scan_id,
                "ip": "192.0.2.10",
                "network_user": "netuser-lab",
                "ssh_credentials_ref": "lab-only-not-a-real-secret",
                "has_sudo": true,
                "requested_by": "google-sub-123",
            })]
        );
        assert!(!h.published()[0]
            .as_object()
            .unwrap()
            .contains_key("scan_mode"));
        assert_eq!(
            h.stub.count("profile"),
            0,
            "ssh no consulta el permiso de red"
        );
        if let Some(validator) = broker_schema("scan-request.schema.json") {
            assert!(validator.is_valid(&h.published()[0]));
        }
    }
}

#[tokio::test]
async fn ssh_mode_keeps_accepting_targets_the_network_denylist_would_reject() {
    // La denylist es solo del modo network: ssh queda como estaba.
    let h = harness(false).await;
    assert_eq!(
        h.post(json!({"target": "127.0.0.1"})).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn unknown_mode_is_rejected_and_nothing_happens() {
    let h = harness(true).await;
    for mode in [json!("nmap"), json!("NETWORK"), json!(7), json!(null)] {
        let response = h.post(json!({"target": "192.0.2.10", "mode": mode})).await;
        assert!(
            response.status().is_client_error(),
            "{mode}: {}",
            response.status()
        );
    }
    h.assert_nothing_happened();
}

// --- Rate limit, eventos, /api/me, historial, OpenAPI -----------------------

#[tokio::test]
async fn network_scans_share_the_rate_limit_with_ssh_scans() {
    let h = harness_with(
        json!({"role": "user", "can_network_scan": true}),
        Options {
            rate_limit: 2,
            ..Options::default()
        },
    )
    .await;

    assert_eq!(
        h.post(json!({"target": "192.0.2.10"})).await.status(),
        StatusCode::OK
    );
    assert_eq!(h.post(network("192.0.2.11")).await.status(), StatusCode::OK);
    assert_eq!(
        h.post(network("192.0.2.12")).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(h.published().len(), 2);
}

#[tokio::test]
async fn scan_requested_event_carries_scan_mode_for_network_and_stays_unchanged_for_ssh() {
    let events = Arc::new(RecordingSecurityEventPublisher::new());
    let h = harness_with(
        json!({"role": "user", "can_network_scan": true}),
        Options {
            events: events.clone(),
            ..Options::default()
        },
    )
    .await;

    assert_eq!(h.post(network("192.0.2.10")).await.status(), StatusCode::OK);
    assert_eq!(
        h.post(json!({"target": "192.0.2.11"})).await.status(),
        StatusCode::OK
    );
    // Un rechazo no emite `scan.requested`.
    assert_eq!(
        h.post(network("127.0.0.1")).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let emitted = events.wait_for(2).await;
    assert_eq!(emitted.len(), 2);
    // El orden de llegada de los eventos no está garantizado: se buscan por
    // su `payload.target`.
    let find = |target: &str| {
        emitted
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .find(|event| event["payload"]["target"] == target)
            .unwrap_or_else(|| panic!("no hay evento para {target}"))
    };
    let network_event = find("192.0.2.10");
    let ssh_event = find("192.0.2.11");
    assert_eq!(network_event["event_type"], "scan.requested");
    assert_eq!(
        network_event["payload"],
        json!({"target": "192.0.2.10", "scan_mode": "network"})
    );
    assert_eq!(ssh_event["payload"], json!({"target": "192.0.2.11"}));
    if let Some(validator) = broker_schema("security-event.schema.json") {
        assert!(validator.is_valid(&network_event));
        assert!(validator.is_valid(&ssh_event));
    }
}

#[tokio::test]
async fn api_me_exposes_can_network_scan_from_the_live_profile() {
    let cases = [
        (json!({"role": "user", "can_network_scan": true}), true),
        (json!({"role": "user", "can_network_scan": false}), false),
        (json!({"role": "user"}), false),
    ];
    for (profile, expected) in cases {
        let h = harness_with(profile.clone(), Options::default()).await;
        let body: Value = h.get("/api/me").await.json().await.expect("json");
        assert_eq!(body["can_network_scan"], expected, "{profile}");
        assert_eq!(body["role"], "user");
        assert_eq!(body["email"], "user@example.com");
    }
}

#[tokio::test]
async fn api_me_reports_false_when_user_service_fails() {
    let h = harness(true).await;
    h.stub.set_profile(500, json!({}));

    let response = h.get("/api/me").await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/api/me no se cae con user-service"
    );
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["can_network_scan"], false);
}

#[tokio::test]
async fn history_entries_expose_the_scan_mode() {
    let h = harness(true).await;
    assert_eq!(
        h.post(json!({"target": "192.0.2.10"})).await.status(),
        StatusCode::OK
    );
    assert_eq!(h.post(network("192.0.2.11")).await.status(), StatusCode::OK);

    let body: Value = h.get("/api/scans").await.json().await.expect("json");

    let entries = body.as_array().expect("lista");
    let mode_of = |target: &str| {
        entries
            .iter()
            .find(|e| e["target"] == target)
            .map(|e| e["mode"].clone())
            .expect("entrada")
    };
    assert_eq!(mode_of("192.0.2.10"), "ssh");
    assert_eq!(mode_of("192.0.2.11"), "network");
}

#[tokio::test]
async fn network_scan_sends_scan_mode_to_the_history_and_ssh_body_is_unchanged() {
    let h = harness(true).await;
    assert_eq!(
        h.post(json!({"target": "192.0.2.10"})).await.status(),
        StatusCode::OK
    );
    assert_eq!(h.post(network("192.0.2.11")).await.status(), StatusCode::OK);

    let bodies = h.stub.create_bodies.lock().expect("lock").clone();
    assert_eq!(bodies[0], json!({"target": "192.0.2.10"}));
    assert_eq!(
        bodies[1],
        json!({"target": "192.0.2.11", "scan_mode": "network"})
    );
}

#[tokio::test]
async fn mode_survives_a_gateway_restart_because_it_comes_from_the_history() {
    let (url, stub) = spawn_usuarios_stub(json!({"role": "user", "can_network_scan": true})).await;
    let first = spawn_gateway(
        url.clone(),
        Arc::new(RecordingPublisher::default()),
        Options::default(),
    )
    .await;
    let post = reqwest::Client::new()
        .post(format!("http://{}/api/scans", first.addr))
        .header(reqwest::header::COOKIE, cookie())
        .json(&network("192.0.2.11"))
        .send()
        .await
        .expect("POST");
    assert_eq!(post.status(), StatusCode::OK);
    assert_eq!(stub.count("history"), 1);

    // Reinicio: gateway nuevo, registro en memoria vacío, mismo `ms-usuarios`.
    let restarted = spawn_gateway(
        url,
        Arc::new(RecordingPublisher::default()),
        Options::default(),
    )
    .await;
    let body: Value = reqwest::Client::new()
        .get(format!("http://{}/api/scans", restarted.addr))
        .header(reqwest::header::COOKIE, cookie())
        .send()
        .await
        .expect("GET")
        .json()
        .await
        .expect("json");

    let entry = &body.as_array().expect("lista")[0];
    assert_eq!(entry["mode"], "network");
    assert!(entry.get("scanId").is_none(), "el scanId sí se pierde");
}

#[tokio::test]
async fn mode_falls_back_to_the_registry_when_the_history_does_not_carry_it() {
    let h = harness(true).await;
    h.stub.legacy_history.store(true, Ordering::SeqCst);
    assert_eq!(h.post(network("192.0.2.11")).await.status(), StatusCode::OK);

    let body: Value = h.get("/api/scans").await.json().await.expect("json");

    assert_eq!(body[0]["mode"], "network");
}

#[tokio::test]
async fn mode_is_omitted_when_neither_history_nor_registry_know_it() {
    let (url, stub) = spawn_usuarios_stub(json!({"role": "user", "can_network_scan": true})).await;
    stub.legacy_history.store(true, Ordering::SeqCst);
    stub.history.lock().expect("lock").push(json!({
        "scan_id": "old-1", "user_id": "google-sub-123", "target": "192.0.2.9",
        "status": "COMPLETADO", "requested_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z", "failure_reason": null,
    }));
    let gateway = spawn_gateway(
        url,
        Arc::new(RecordingPublisher::default()),
        Options::default(),
    )
    .await;

    let body: Value = reqwest::Client::new()
        .get(format!("http://{}/api/scans", gateway.addr))
        .header(reqwest::header::COOKIE, cookie())
        .send()
        .await
        .expect("GET")
        .json()
        .await
        .expect("json");

    assert!(body[0].get("mode").is_none());
}

#[tokio::test]
async fn openapi_documents_mode_403_422_503_and_can_network_scan() {
    let h = harness(true).await;
    let spec: Value = h.get("/api/openapi.json").await.json().await.expect("json");

    let schemas = &spec["components"]["schemas"];
    assert!(schemas["ScanMode"].is_object(), "falta el schema ScanMode");
    assert_eq!(schemas["ScanMode"]["enum"], json!(["ssh", "network"]));
    assert!(schemas["ScanSubmissionRequest"]["properties"]["mode"].is_object());
    assert!(schemas["MeResponse"]["properties"]["can_network_scan"].is_object());
    assert!(schemas["ScanHistoryEntryResponse"]["properties"]["mode"].is_object());
    let responses = &spec["paths"]["/api/scans"]["post"]["responses"];
    for status in ["403", "422", "503"] {
        assert!(
            responses[status].is_object(),
            "falta {status} en POST /api/scans"
        );
    }
}
