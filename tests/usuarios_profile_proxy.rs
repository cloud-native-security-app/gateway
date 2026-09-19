//! Tests de integración de la feature `usuarios_profile_proxy`, ruta
//! `GET /api/profile`.
//!
//! Ejercen el router real de `gateway::api::app_router` servido sobre un
//! puerto efímero con `axum::serve` (mismo patrón que
//! `tests/session_middleware_and_me.rs`), con `AppState::usuarios_client`
//! apuntando a un stub HTTP real de `ms-usuarios` — nunca a `user-service`
//! de producción (ver `docs/verification.md` Nivel 3).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use gateway::api::{app_router, AppState};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::domain::Session;
use gateway::usuarios_client::UsuariosClient;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const MS_USUARIOS_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

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
/// patrón que `tests/session_middleware_and_me.rs`).
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

/// Stub mínimo de `ms-usuarios` que siempre devuelve `fixed_profile` a
/// `GET /users/me`, sin validar credenciales (los tests que sí ejercen ese
/// camino viven en `tests/usuarios_client.rs`).
async fn spawn_happy_usuarios_stub(fixed_profile: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let app = Router::new().route("/users/me", get(move || async move { Json(fixed_profile) }));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

/// URL base sobre la que no hay ningún servidor escuchando: simula
/// `ms-usuarios` caído (mismo patrón que `tests/usuarios_client.rs`).
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

#[tokio::test]
async fn profile_with_valid_session_and_healthy_ms_usuarios_returns_the_profile() {
    let fixed_profile = json!({
        "sub": "google-sub-123",
        "email": "user@example.com",
        "display_name": "Test User",
    });
    let usuarios_base_url = spawn_happy_usuarios_stub(fixed_profile.clone()).await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/profile", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .send()
        .await
        .expect("GET /api/profile debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: Value = response.json().await.expect("cuerpo JSON válido");
    assert_eq!(body, fixed_profile);
}

#[tokio::test]
async fn profile_without_session_cookie_is_rejected_before_touching_ms_usuarios() {
    // Apunta a una URL sobre la que no hay nada escuchando: si el
    // middleware de sesión dejara pasar la solicitud igual, el intento de
    // contactar a ms-usuarios fallaría de un modo distinto a 401, delatando
    // el bug.
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/profile", gateway.addr))
        .send()
        .await
        .expect("GET /api/profile debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn profile_when_ms_usuarios_is_unreachable_returns_a_gateway_error_without_leaking_its_url() {
    let usuarios_base_url = unreachable_usuarios_base_url().await;
    let gateway = spawn_gateway(usuarios_base_url.clone()).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/profile", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .send()
        .await
        .expect("GET /api/profile debe responder");

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
