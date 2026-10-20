//! Tests de integración de la feature `cors_for_front`.
//!
//! Ejercen el router real de `gateway::api::app_router` (mismo patrón que
//! `tests/session_middleware_and_me.rs`) servido sobre un puerto efímero
//! con `axum::serve`. El `OidcClient` de `AppState` se resuelve contra un
//! IdP de prueba mínimo (solo el documento de discovery, nunca el endpoint
//! real de Google), porque esta feature no ejercita el login en sí: solo
//! necesita un `AppState` completo para poder construir `app_router` y
//! ejercer la `CorsLayer` que envuelve todo el router (RF-01, ver
//! `docs/architecture.md`).
//!
//! Contexto del bug real que motiva esta feature: `front` corre en un
//! origen distinto de este Gateway (mismo host, puerto distinto) y llama a
//! `GET /api/me` con `fetch(..., { credentials: "include" })`. Sin
//! cabeceras CORS, el navegador bloquea la respuesta aunque este Gateway la
//! procese bien, y `front` lo trata como sesión anónima -> bucle de
//! redirect a `/auth/login`. No se puede reproducir ese bloqueo del
//! navegador desde un test de servidor (`reqwest` no lo aplica), así que
//! estos tests verifican las cabeceras que el navegador exige para *no*
//! bloquear la respuesta, y la ausencia de esas cabeceras para un origen no
//! permitido.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::HeaderValue;
use axum::routing::get;
use axum::{Json, Router};
use gateway::api::{app_router, AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
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
/// URL de `front` de laboratorio a la que redirigiría un login exitoso
/// (feature `post_login_redirect`) — incluye `path`, como en un valor real
/// de `FRONT_BASE_URL` (ver `README.md`), a propósito: demuestra que el
/// origen permitido por CORS ([`TEST_FRONT_ORIGIN`]) es distinto de este
/// valor (un header `Origin` de navegador nunca lleva `path`).
const TEST_FRONT_BASE_URL: &str = "https://front.lab/post-login";
/// Origen (sin `path`) de [`TEST_FRONT_BASE_URL`] — el único que la
/// `CorsLayer` de `app_router` debe reflejar en
/// `Access-Control-Allow-Origin`.
const TEST_FRONT_ORIGIN: &str = "https://front.lab";
/// Origen que **no** es [`TEST_FRONT_ORIGIN`]: nunca debe recibir
/// `Access-Control-Allow-Origin`.
const DISALLOWED_ORIGIN: &str = "https://evil.example";

/// Doble de prueba de [`ScanRequestPublisher`]: esta feature (`cors_for_front`)
/// no ejerce el envío de escaneos, así que un `AppState` de prueba solo
/// necesita satisfacer el tipo del campo, nunca invocarlo de verdad.
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

    // Esta feature no ejerce `usuarios_client` (solo CORS + `/api/me`):
    // apunta a una URL de laboratorio que nunca se contacta en estos tests.
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
        front_base_url: TEST_FRONT_BASE_URL.to_string(),
        front_origin: HeaderValue::from_static(TEST_FRONT_ORIGIN),
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

/// Criterio de aceptación 1/2 (parcial): una request real con el `Origin`
/// configurado (`FRONT_BASE_URL`, sin `path`) a una ruta protegida recibe
/// `Access-Control-Allow-Origin` con ese mismo valor y
/// `Access-Control-Allow-Credentials: true` — sin esto, el navegador
/// bloquea la respuesta de `GET /api/me` aunque este Gateway la procese
/// bien (causa raíz del bucle de redirect a `/auth/login` en despliegue
/// real).
#[tokio::test]
async fn get_me_with_allowed_origin_receives_correct_cors_headers() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(reqwest::header::ORIGIN, TEST_FRONT_ORIGIN)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "una request real con Origin permitido y sesión válida sigue debiendo ejecutar el handler"
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("debe llevar Access-Control-Allow-Origin"),
        TEST_FRONT_ORIGIN,
        "el origen reflejado debe ser exactamente FRONT_BASE_URL (sin path), nunca un wildcard"
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-credentials")
            .expect("debe llevar Access-Control-Allow-Credentials"),
        "true"
    );
}

/// Criterio de aceptación 2: un preflight `OPTIONS` a una ruta protegida
/// (`/api/me`, que lleva `require_session`) responde 200/204 con las
/// cabeceras CORS correctas **sin** cookie de sesión — un preflight real de
/// navegador nunca la envía, y el middleware de sesión nunca debe
/// exigírsela. La `CorsLayer` se aplica como capa externa en `app_router`
/// precisamente para que esto sea así (ver `src/api.rs::app_router`).
#[tokio::test]
async fn preflight_options_to_protected_route_does_not_require_session() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{}/api/me", gateway.addr),
        )
        .header(reqwest::header::ORIGIN, TEST_FRONT_ORIGIN)
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .expect("el preflight OPTIONS debe responder");

    assert!(
        response.status() == reqwest::StatusCode::OK
            || response.status() == reqwest::StatusCode::NO_CONTENT,
        "un preflight OPTIONS debe responder 200/204, no {}",
        response.status()
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("el preflight debe llevar Access-Control-Allow-Origin"),
        TEST_FRONT_ORIGIN
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-credentials")
            .expect("el preflight debe llevar Access-Control-Allow-Credentials"),
        "true"
    );
}

/// Criterio de aceptación 3: una request con un `Origin` distinto al
/// configurado no recibe `Access-Control-Allow-Origin` (el navegador la
/// bloquearía) — pero este Gateway igual la procesa normalmente del lado
/// del servidor (CORS es una restricción del navegador sobre la
/// *respuesta*, no una capa de autorización propia de este Gateway).
#[tokio::test]
async fn get_me_with_disallowed_origin_does_not_receive_allow_origin_header() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(reqwest::header::ORIGIN, DISALLOWED_ORIGIN)
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={}", valid_session_cookie_value()),
        )
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "CORS no cambia la autorización: una sesión válida sigue viendo su propia identidad"
    );
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "un origen no permitido nunca debe recibir Access-Control-Allow-Origin"
    );
}

/// Criterio de aceptación "una request real sigue exigiendo sesión válida
/// igual que antes": CORS solo habilita que el navegador lea la respuesta,
/// nunca reemplaza al middleware de sesión de una request real (no
/// preflight), incluso con el `Origin` permitido.
#[tokio::test]
async fn get_me_with_allowed_origin_but_without_session_is_still_rejected() {
    let gateway = spawn_gateway().await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/api/me", gateway.addr))
        .header(reqwest::header::ORIGIN, TEST_FRONT_ORIGIN)
        .send()
        .await
        .expect("GET /api/me debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
