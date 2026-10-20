//! Tests de integración de la feature `network_credentials_proxy`, rutas
//! `GET`/`POST /api/network-credentials` y `DELETE
//! /api/network-credentials/{id}`.
//!
//! Ejercen el router real de `gateway::api::app_router` servido sobre un
//! puerto efímero con `axum::serve` (mismo patrón que
//! `tests/usuarios_profile_proxy.rs`), con `AppState::usuarios_client`
//! apuntando a un stub HTTP real que implementa el contrato ya documentado
//! de `user-service` (`POST`/`GET /users/me/network-credentials`, `DELETE
//! /users/me/network-credentials/{id}`) — nunca a `user-service` de
//! producción (ver `docs/verification.md` Nivel 3).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::Session;
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::{
    UsuariosClient, FORWARDED_USER_HEADER_NAME, GATEWAY_SECRET_HEADER_NAME,
};
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const MS_USUARIOS_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

/// Doble de prueba de [`ScanRequestPublisher`]: esta feature
/// (`network_credentials_proxy`) no ejerce `POST /api/scans`, así que un
/// `AppState` de prueba solo necesita satisfacer el tipo del campo, nunca
/// invocarlo de verdad.
struct NeverPublishesToBroker;

#[async_trait::async_trait]
impl ScanRequestPublisher for NeverPublishesToBroker {
    async fn publish_scan_request(&self, _request: &ScanRequest) -> Result<(), BrokerError> {
        panic!("esta prueba no debe llegar a publicar en el Broker");
    }

    async fn publish_scan_cancellation(
        &self,
        _cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        panic!("esta prueba no debe llegar a publicar una cancelación en el Broker");
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

fn secret_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(GATEWAY_SECRET_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        == Some(expected)
}

/// Estado del stub de `ms-usuarios` de prueba: qué credencial de servicio
/// exige y qué credenciales de red tiene almacenadas en un momento dado.
#[derive(Clone)]
struct NetworkCredentialsStubState {
    expected_secret: String,
    credentials: Arc<Mutex<Vec<Value>>>,
}

/// Construye la entrada `NetworkCredential` que `ms-usuarios` reportaría
/// para `payload` (el cuerpo de `POST /users/me/network-credentials`).
/// Incluye deliberadamente `ssh_credentials_ref` en la respuesta simulada de
/// este stub (algo que `user-service` real nunca hace, ver
/// `user-service/src/domain.rs::NetworkCredential`) para probar que
/// `crate::usuarios_client::NetworkCredential` la descarta al deserializar
/// -- el tipo Rust de este Gateway no tiene ese campo, así que no podría
/// reenviarla a `front` aunque `ms-usuarios` fallara y la incluyera.
fn credential_from_payload(id: &str, payload: &Value) -> Value {
    json!({
        "id": id,
        "user_id": "google-sub-123",
        "target_pattern": payload["target_pattern"],
        "network_user": payload["network_user"],
        "has_sudo": payload["has_sudo"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "ssh_credentials_ref": payload.get("ssh_credentials_ref").cloned().unwrap_or(Value::Null),
    })
}

async fn get_network_credentials(
    State(state): State<NetworkCredentialsStubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if !secret_matches(&headers, &state.expected_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "credencial de servicio inválida"})),
        );
    }
    if headers.get(FORWARDED_USER_HEADER_NAME).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "falta el header de identidad"})),
        );
    }

    let credentials = state
        .credentials
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    (StatusCode::OK, Json(Value::Array(credentials)))
}

async fn post_network_credentials(
    State(state): State<NetworkCredentialsStubState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !secret_matches(&headers, &state.expected_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "credencial de servicio inválida"})),
        );
    }

    let mut credentials = state
        .credentials
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let id = format!("cred-{}", credentials.len() + 1);
    let saved = credential_from_payload(&id, &payload);
    credentials.push(saved.clone());
    (StatusCode::OK, Json(saved))
}

async fn delete_network_credential(
    State(state): State<NetworkCredentialsStubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> StatusCode {
    if !secret_matches(&headers, &state.expected_secret) {
        return StatusCode::UNAUTHORIZED;
    }

    let mut credentials = state
        .credentials
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let before = credentials.len();
    credentials.retain(|entry| entry["id"] != id);

    if credentials.len() < before {
        StatusCode::NO_CONTENT
    } else {
        // Mismo criterio que `user-service` real: un id inexistente o de
        // otro usuario responde 404, nunca 403 (ver
        // `docs/security-scope.md`).
        StatusCode::NOT_FOUND
    }
}

/// Levanta el stub de `ms-usuarios` con `expected_secret` como credencial de
/// servicio válida y `initial_credentials` como colección inicial.
async fn spawn_stub(expected_secret: &str, initial_credentials: Vec<Value>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let state = NetworkCredentialsStubState {
        expected_secret: expected_secret.to_string(),
        credentials: Arc::new(Mutex::new(initial_credentials)),
    };

    let app = Router::new()
        .route(
            "/users/me/network-credentials",
            get(get_network_credentials).post(post_network_credentials),
        )
        .route(
            "/users/me/network-credentials/:id",
            axum::routing::delete(delete_network_credential),
        )
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

/// URL base sobre la que no hay ningún servidor escuchando: simula
/// `ms-usuarios` caído (mismo patrón que `tests/usuarios_profile_proxy.rs`).
async fn unreachable_usuarios_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temporal para reservar un puerto libre");
    let addr = listener.local_addr().expect("addr temporal");
    drop(listener);
    format!("http://{addr}")
}

struct GatewayUnderTest {
    addr: SocketAddr,
}

async fn spawn_gateway(usuarios_base_url: String) -> GatewayUnderTest {
    spawn_gateway_with_secret(usuarios_base_url, MS_USUARIOS_SHARED_SECRET).await
}

async fn spawn_gateway_with_secret(
    usuarios_base_url: String,
    shared_secret: &str,
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
        SecretString::from(shared_secret.to_string()),
    )
    .expect("cliente de laboratorio hacia ms-usuarios debe construirse");

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
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
        realtime: Arc::new(RealtimeRegistry::new()),
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

    GatewayUnderTest { addr }
}

fn http_client_no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("cliente http de prueba")
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

fn session_cookie_header() -> (reqwest::header::HeaderName, String) {
    (
        reqwest::header::COOKIE,
        format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
    )
}

#[tokio::test]
async fn list_network_credentials_happy_path_returns_the_credentials_without_ssh_ref() {
    let existing = credential_from_payload(
        "cred-1",
        &json!({
            "target_pattern": "192.0.2.0/24",
            "network_user": "netuser",
            "has_sudo": false,
            "ssh_credentials_ref": "lab-only-not-a-real-secret",
        }),
    );
    let usuarios_base_url = spawn_stub(MS_USUARIOS_SHARED_SECRET, vec![existing]).await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .get(format!("http://{}/api/network-credentials", gateway.addr))
        .header(cookie_name, cookie_value)
        .send()
        .await
        .expect("GET /api/network-credentials debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: Value = response.json().await.expect("cuerpo JSON válido");
    let entries = body.as_array().expect("debe ser un arreglo");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "cred-1");
    assert_eq!(entries[0]["target_pattern"], "192.0.2.0/24");
    assert!(
        entries[0].get("ssh_credentials_ref").is_none(),
        "la respuesta jamás debe incluir ssh_credentials_ref, obtuve: {entries:?}"
    );
}

#[tokio::test]
async fn create_network_credential_happy_path_returns_the_saved_credential_without_ssh_ref() {
    let usuarios_base_url = spawn_stub(MS_USUARIOS_SHARED_SECRET, vec![]).await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .post(format!("http://{}/api/network-credentials", gateway.addr))
        .header(cookie_name, cookie_value)
        .json(&json!({
            "target_pattern": "198.51.100.10",
            "network_user": "netuser",
            "ssh_credentials_ref": "lab-only-not-a-real-secret",
            "has_sudo": true,
        }))
        .send()
        .await
        .expect("POST /api/network-credentials debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: Value = response.json().await.expect("cuerpo JSON válido");
    assert_eq!(body["target_pattern"], "198.51.100.10");
    assert_eq!(body["network_user"], "netuser");
    assert_eq!(body["has_sudo"], true);
    assert!(
        body.get("ssh_credentials_ref").is_none(),
        "la respuesta jamás debe incluir ssh_credentials_ref, obtuve: {body:?}"
    );
}

#[tokio::test]
async fn delete_network_credential_happy_path_returns_no_content() {
    let existing = credential_from_payload(
        "cred-1",
        &json!({
            "target_pattern": "192.0.2.0/24",
            "network_user": "netuser",
            "has_sudo": false,
        }),
    );
    let usuarios_base_url = spawn_stub(MS_USUARIOS_SHARED_SECRET, vec![existing]).await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .delete(format!(
            "http://{}/api/network-credentials/cred-1",
            gateway.addr
        ))
        .header(cookie_name, cookie_value)
        .send()
        .await
        .expect("DELETE /api/network-credentials/cred-1 debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_network_credential_of_an_unknown_or_foreign_entry_returns_not_found() {
    let usuarios_base_url = spawn_stub(MS_USUARIOS_SHARED_SECRET, vec![]).await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .delete(format!(
            "http://{}/api/network-credentials/does-not-exist",
            gateway.addr
        ))
        .header(cookie_name, cookie_value)
        .send()
        .await
        .expect("DELETE /api/network-credentials/does-not-exist debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn network_credentials_without_session_cookie_are_rejected_before_touching_ms_usuarios() {
    // Apunta a una URL sobre la que no hay nada escuchando: si el middleware
    // de sesión dejara pasar la solicitud igual, el intento de contactar a
    // ms-usuarios fallaría de un modo distinto a 401, delatando el bug.
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/network-credentials", gateway.addr))
        .send()
        .await
        .expect("GET /api/network-credentials debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn network_credentials_with_rejected_service_credential_returns_a_generic_gateway_error() {
    // El Gateway está configurado con un secreto distinto al que exige el
    // stub de ms-usuarios: éste responde 401, que este Gateway traduce al
    // 502 genérico del resto de fallos de ms-usuarios (nunca expone el
    // detalle real al cliente, ver `docs/security-scope.md`).
    let usuarios_base_url = spawn_stub("correct-secret-lab-only", vec![]).await;
    let gateway = spawn_gateway_with_secret(usuarios_base_url, "wrong-secret-lab-only").await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .get(format!("http://{}/api/network-credentials", gateway.addr))
        .header(cookie_name, cookie_value)
        .send()
        .await
        .expect("GET /api/network-credentials debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn network_credentials_when_ms_usuarios_is_unreachable_returns_a_gateway_error_without_leaking_its_url(
) {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url.clone()).await;
    let http = http_client_no_redirects();
    let (cookie_name, cookie_value) = session_cookie_header();

    let response = http
        .get(format!("http://{}/api/network-credentials", gateway.addr))
        .header(cookie_name, cookie_value)
        .send()
        .await
        .expect("GET /api/network-credentials debe responder");

    assert!(
        response.status() == StatusCode::BAD_GATEWAY
            || response.status() == StatusCode::GATEWAY_TIMEOUT,
        "ms-usuarios caído debe responder 502 o 504, obtuve {}",
        response.status()
    );

    let body = response.text().await.expect("debe poder leer el cuerpo");
    assert!(
        !body.contains(&usuarios_base_url),
        "el cuerpo de error no debe exponer la URL interna de ms-usuarios: {body}"
    );
}
