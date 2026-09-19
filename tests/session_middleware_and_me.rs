//! Tests de integración de la feature `session_middleware_and_me`.
//!
//! Ejercen el router real de `gateway::api::app_router` (login/callback/
//! logout/salud/`/api/me`) servido sobre un puerto efímero con
//! `axum::serve`, igual que `tests/oidc_login.rs`. El `OidcClient` de
//! `AppState` se resuelve contra un IdP de prueba mínimo (solo el documento
//! de discovery, nunca el endpoint real de Google — ver
//! `docs/verification.md` Nivel 3), porque esta feature no ejercita el
//! login en sí, solo necesita un `AppState` completo para poder construir
//! `app_router`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ROUTES};
use gateway::auth::{issue_session_token, LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use gateway::domain::Session;
use gateway::realtime::RealtimeRegistry;
use gateway::usuarios_client::UsuariosClient;
use jsonwebtoken::jwk::JwkSet;
use secrecy::SecretString;
use serde_json::json;
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";

/// Doble de prueba de [`ScanRequestPublisher`]: esta feature
/// (`session_middleware_and_me`) no ejerce el envío de escaneos con una
/// sesión válida, así que un `AppState` de prueba solo necesita satisfacer
/// el tipo del campo, nunca invocarlo de verdad.
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

async fn serve_discovery(State(issuer_url): State<String>) -> Json<serde_json::Value> {
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

async fn serve_empty_jwks() -> Json<JwkSet> {
    Json(JwkSet { keys: vec![] })
}

/// IdP OIDC de prueba mínimo: sirve el documento de discovery y un JWKS
/// vacío (`OidcClient::discover` también resuelve el JWKS al hacer
/// discovery). Esta feature no ejercita el intercambio de código/ID token,
/// así que no necesita más.
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

/// Instancia del router completo de este Gateway bajo prueba, ya
/// escuchando en un puerto efímero.
struct GatewayUnderTest {
    addr: SocketAddr,
}

async fn spawn_gateway() -> GatewayUnderTest {
    let issuer_url = spawn_discovery_only_idp().await;

    let oidc_client = OidcClient::discover(
        &issuer_url,
        TEST_CLIENT_ID,
        &SecretString::from("test-client-secret".to_string()),
        TEST_REDIRECT_URI,
    )
    .await
    .expect("discovery contra el IdP de prueba debe funcionar");

    // Esta feature no ejercita `usuarios_client` (solo enumera rutas y
    // valida `/api/me`): apunta a una URL de laboratorio que nunca se
    // contacta en estos tests.
    let usuarios_client = UsuariosClient::new(
        "http://ms-usuarios.invalid".to_string(),
        SecretString::from("lab-only-not-a-real-secret".to_string()),
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
        broker_publisher: Arc::new(NeverPublishesToBroker),
        scan_ownership: Arc::new(ScanOwnershipRegistry::new()),
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

fn lab_session() -> Session {
    Session {
        sub: "google-sub-123".to_string(),
        email: "user@example.com".to_string(),
        name: "Test User".to_string(),
        exp: now_epoch_secs() + 3600,
    }
}

fn valid_session_cookie_value() -> String {
    issue_session_token(
        &lab_session(),
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("debe poder firmar una sesión de laboratorio válida")
}

/// Enumera cada ruta declarada en [`gateway::api::ROUTES`] (la tabla
/// canónica que también usa `app_router` para construirse) y verifica, sin
/// cookie de sesión, que las rutas marcadas `protected: true` responden
/// `401` y las marcadas `protected: false` no. Así una ruta nueva que se
/// añada a `app_router` sin añadirse a `ROUTES` (o viceversa) deja de
/// reflejar el router real, en vez de quedar protegida o desprotegida por
/// accidente en silencio.
#[tokio::test]
async fn enumerates_routes_and_verifies_which_carry_the_session_middleware() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    assert!(
        ROUTES.iter().any(|r| r.path == "/api/me" && r.protected),
        "la tabla ROUTES debe listar /api/me como protegida"
    );
    assert!(
        ROUTES
            .iter()
            .any(|r| r.path == "/auth/login" && !r.protected),
        "la tabla ROUTES debe listar /auth/login como pública"
    );
    assert!(
        ROUTES
            .iter()
            .any(|r| r.path == "/auth/callback" && !r.protected),
        "la tabla ROUTES debe listar /auth/callback como pública"
    );
    assert!(
        ROUTES.iter().any(|r| r.path == "/health" && !r.protected),
        "la tabla ROUTES debe listar /health como pública"
    );

    for route in ROUTES {
        let method = reqwest::Method::from_bytes(route.method.as_bytes())
            .expect("método HTTP válido en ROUTES");
        let response = http
            .request(method, format!("http://{}{}", gateway.addr, route.path))
            .send()
            .await
            .unwrap_or_else(|err| panic!("{} {} debe responder: {err}", route.method, route.path));

        if route.protected {
            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "{} {} está marcada como protegida en ROUTES pero no exigió sesión",
                route.method,
                route.path
            );
        } else {
            assert_ne!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "{} {} está marcada como pública en ROUTES pero exigió sesión",
                route.method,
                route.path
            );
        }
    }
}

#[tokio::test]
async fn me_with_valid_session_returns_the_session_identity() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("cuerpo JSON válido");
    assert_eq!(body["sub"], "google-sub-123");
    assert_eq!(body["email"], "user@example.com");
    assert_eq!(body["name"], "Test User");
}

#[tokio::test]
async fn me_without_session_cookie_is_rejected() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_with_invalid_signature_session_is_rejected() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let token_signed_with_wrong_key = issue_session_token(
        &lab_session(),
        &SecretString::from("a-completely-different-lab-key".to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("debe poder firmar con otra clave de laboratorio");

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={token_signed_with_wrong_key}"),
        )
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_with_expired_session_is_rejected() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let mut expired_session = lab_session();
    expired_session.exp = now_epoch_secs() - 3600;

    let expired_token = issue_session_token(
        &expired_session,
        &SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("debe poder firmar una sesión ya vencida");

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={expired_token}"),
        )
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
