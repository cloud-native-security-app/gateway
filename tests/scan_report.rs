//! Tests de integración de la feature `scan-report`: `GET
//! /api/scans/{scan_id}/report`.
//!
//! Ejercen el router real (`gateway::api::app_router`) contra un stub HTTP
//! real de `ms-usuarios` (`GET /users/me/scans/{id}/report`), con
//! `AppState::scan_ownership` poblado a mano. No necesitan Docker.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderValue, StatusCode};
use axum::routing::get;
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

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";

struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("estos tests no publican en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("estos tests no publican en el Broker");
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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind IdP");
    let issuer_url = format!("http://{}", listener.local_addr().expect("addr IdP"));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(serve_discovery))
        .route("/jwks", get(serve_empty_jwks))
        .with_state(issuer_url.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("servidor IdP");
    });
    issuer_url
}

/// Ids de `ms-usuarios` consultados por el Gateway en el stub del reporte.
type RequestedIds = Arc<Mutex<Vec<String>>>;

#[derive(Clone)]
struct ReportStub {
    status: StatusCode,
    body: Value,
    requested: RequestedIds,
}

async fn serve_report(
    State(stub): State<ReportStub>,
    AxumPath(scan_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    stub.requested.lock().unwrap().push(scan_id);
    (stub.status, Json(stub.body))
}

async fn spawn_report_stub(status: StatusCode, body: Value) -> (String, RequestedIds) {
    let requested: RequestedIds = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("addr stub");
    let app = Router::new()
        .route("/users/me/scans/:scan_id/report", get(serve_report))
        .with_state(ReportStub {
            status,
            body,
            requested: requested.clone(),
        });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("servidor stub");
    });
    (format!("http://{addr}"), requested)
}

async fn unreachable_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

struct GatewayUnderTest {
    addr: std::net::SocketAddr,
    scan_ownership: Arc<ScanOwnershipRegistry>,
}

async fn spawn_gateway(usuarios_base_url: String) -> GatewayUnderTest {
    let issuer_url = spawn_discovery_only_idp().await;
    let oidc_client = OidcClient::discover(
        &issuer_url,
        "test-client-id",
        &SecretString::from("test-client-secret".to_string()),
        "http://gateway.lab/auth/callback",
    )
    .await
    .expect("discovery contra el IdP de prueba");
    let scan_ownership = Arc::new(ScanOwnershipRegistry::new());
    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: SecretString::from(SESSION_SIGNING_KEY.to_string()),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        front_base_url: "https://front.lab".to_string(),
        front_origin: HeaderValue::from_static("https://front.lab"),
        usuarios_client: Arc::new(
            UsuariosClient::new(
                usuarios_base_url,
                SecretString::from(SESSION_SIGNING_KEY.to_string()),
            )
            .expect("cliente de laboratorio"),
        ),
        broker_publisher: Arc::new(NeverPublishesToBroker),
        scan_ownership: scan_ownership.clone(),
        realtime: Arc::new(RealtimeRegistry::new()),
        scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(
            1000,
            Duration::from_secs(60),
        )),
    };
    let app = app_router(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("addr gateway");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("servidor gateway");
    });
    GatewayUnderTest {
        addr,
        scan_ownership,
    }
}

fn session_for(sub: &str) -> Session {
    Session {
        sub: sub.to_string(),
        email: format!("{sub}@example.com"),
        name: "Test User".to_string(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("reloj")
            .as_secs()
            + 3600,
    }
}

fn cookie_for(sub: &str) -> String {
    let token = issue_session_token(
        &session_for(sub),
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("sesión de laboratorio");
    format!("{SESSION_COOKIE_NAME}={token}")
}

fn stored_result() -> Value {
    json!({
        "host": "192.0.2.10",
        "ports": [{
            "port": 80, "protocol": "tcp", "state": "open",
            "service": "http", "version": null, "cpes": ["cpe:/a:apache:http_server"]
        }],
        "vulnerabilities": [{
            "id": "CVE-2024-0001", "severity": "high", "description": "d",
            "nse_script": "vulners", "source": "nmap_nse", "references": []
        }],
        "scanned_at": "2024-01-01T00:00:00Z",
    })
}

async fn get_report(
    gateway: &GatewayUnderTest,
    scan_id: &str,
    cookie: Option<String>,
) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(format!(
        "http://{}/api/scans/{scan_id}/report",
        gateway.addr
    ));
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    request.send().await.expect("GET /report debe responder")
}

#[tokio::test]
async fn report_returns_the_stored_result_translating_the_gateway_scan_id() {
    let (usuarios_url, requested) = spawn_report_stub(StatusCode::OK, stored_result()).await;
    let gateway = spawn_gateway(usuarios_url).await;
    gateway.scan_ownership.register(
        "gw-scan-1",
        "ms-usuarios-9".to_string(),
        session_for("alice"),
    );

    let response = get_report(&gateway, "gw-scan-1", Some(cookie_for("alice"))).await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body, stored_result(), "sin envoltorio, shape de ScanResult");
    assert_eq!(
        *requested.lock().unwrap(),
        vec!["ms-usuarios-9".to_string()]
    );
}

#[tokio::test]
async fn report_without_session_is_unauthorized() {
    let gateway = spawn_gateway(unreachable_base_url().await).await;

    let response = get_report(&gateway, "gw-scan-1", None).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn report_of_an_unknown_or_foreign_scan_is_not_found_without_calling_ms_usuarios() {
    let (usuarios_url, requested) = spawn_report_stub(StatusCode::OK, stored_result()).await;
    let gateway = spawn_gateway(usuarios_url).await;
    gateway
        .scan_ownership
        .register("owned-by-alice", "ms-1".to_string(), session_for("alice"));

    let unknown = get_report(&gateway, "no-existe", Some(cookie_for("alice"))).await;
    let foreign = get_report(&gateway, "owned-by-alice", Some(cookie_for("bob"))).await;

    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(foreign.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(requested.lock().unwrap().is_empty());
}

#[tokio::test]
async fn report_maps_ms_usuarios_404_to_404() {
    let (usuarios_url, _) =
        spawn_report_stub(StatusCode::NOT_FOUND, json!({"error": "no existe"})).await;
    let gateway = spawn_gateway(usuarios_url).await;
    gateway
        .scan_ownership
        .register("gw-scan-1", "ms-1".to_string(), session_for("alice"));

    let response = get_report(&gateway, "gw-scan-1", Some(cookie_for("alice"))).await;

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn report_maps_ms_usuarios_409_to_409_with_a_spanish_error_body() {
    let (usuarios_url, _) = spawn_report_stub(
        StatusCode::CONFLICT,
        json!({"error": "el reporte del escaneo aún no está disponible"}),
    )
    .await;
    let gateway = spawn_gateway(usuarios_url).await;
    gateway
        .scan_ownership
        .register("gw-scan-1", "ms-1".to_string(), session_for("alice"));

    let response = get_report(&gateway, "gw-scan-1", Some(cookie_for("alice"))).await;

    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body = response.text().await.expect("cuerpo");
    assert_eq!(body, "el reporte del escaneo aún no está disponible");
}

#[tokio::test]
async fn report_maps_upstream_failures_to_502_and_unreachable_to_504() {
    let (usuarios_url, _) = spawn_report_stub(StatusCode::INTERNAL_SERVER_ERROR, json!({})).await;
    let failing = spawn_gateway(usuarios_url).await;
    failing
        .scan_ownership
        .register("gw-scan-1", "ms-1".to_string(), session_for("alice"));
    let down = spawn_gateway(unreachable_base_url().await).await;
    down.scan_ownership
        .register("gw-scan-1", "ms-1".to_string(), session_for("alice"));

    let upstream_error = get_report(&failing, "gw-scan-1", Some(cookie_for("alice"))).await;
    let unreachable = get_report(&down, "gw-scan-1", Some(cookie_for("alice"))).await;

    assert_eq!(upstream_error.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(unreachable.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
}
