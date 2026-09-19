//! Tests de integración de la feature `oidc_login`.
//!
//! Ejercen el router real de `gateway::api` (login/callback/logout) contra
//! un IdP OIDC de prueba en memoria (discovery + JWKS + token endpoint
//! propios, servidos con `axum::serve` sobre un puerto efímero) — nunca
//! contra el endpoint real de Google, tal como exige `docs/verification.md`
//! Nivel 3 para `auth`. No dependen de Docker, por lo que corren en
//! `cargo test` normal (decisión confirmada para esta feature, ver
//! `progress/current.md`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gateway::api::{auth_router, AppState};
use gateway::auth::{LoginStateStore, OidcClient, SESSION_COOKIE_NAME};
use gateway::usuarios_client::UsuariosClient;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use secrecy::SecretString;
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;

const TEST_CLIENT_ID: &str = "test-client-id";
const TEST_REDIRECT_URI: &str = "http://gateway.lab/auth/callback";
const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";

/// Par de claves RSA de laboratorio para firmar ID tokens de prueba, más su
/// representación JWK pública. No es una credencial real (ver
/// `docs/security-scope.md`): se genera de cero en cada test.
struct TestKey {
    kid: String,
    private_pem: String,
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestKey {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen RSA de laboratorio");
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("PEM PKCS1 de laboratorio")
        .to_string();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };

    TestKey {
        kid: kid.to_string(),
        private_pem,
        jwk,
    }
}

/// Claims de un ID token de prueba, con todos los campos controlables por
/// cada test (para forzar audiencia incorrecta, expiración, etc.).
#[derive(Serialize)]
struct TestIdTokenClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    email: &'a str,
    name: &'a str,
    exp: i64,
    iat: i64,
    nonce: &'a str,
}

/// Firma `claims` como un JWT RS256 usando la clave privada de `key`,
/// anotando el header `kid` con el `kid` de `key`.
fn sign_id_token(key: &TestKey, claims: &TestIdTokenClaims<'_>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let encoding_key =
        EncodingKey::from_rsa_pem(key.private_pem.as_bytes()).expect("PEM de laboratorio válido");
    jsonwebtoken::encode(&header, claims, &encoding_key).expect("firma de laboratorio")
}

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior al epoch")
        .as_secs() as i64
}

/// Estado compartido por los handlers del IdP de prueba.
#[derive(Clone)]
struct TestIdpState {
    jwks: Arc<JwkSet>,
    issuer_url: String,
    next_id_token: Arc<Mutex<String>>,
}

async fn serve_discovery(State(state): State<TestIdpState>) -> Json<serde_json::Value> {
    let issuer = &state.issuer_url;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn serve_jwks(State(state): State<TestIdpState>) -> Json<JwkSet> {
    Json((*state.jwks).clone())
}

async fn serve_token(State(state): State<TestIdpState>) -> Json<serde_json::Value> {
    let id_token = state
        .next_id_token
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    Json(json!({
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
}

/// IdP OIDC de prueba en memoria: discovery + JWKS + token endpoint propios,
/// servidos en un puerto efímero de `127.0.0.1`. Nunca es el endpoint real
/// de Google (ver `docs/verification.md` Nivel 3, sección `auth`).
struct TestIdp {
    issuer_url: String,
    next_id_token: Arc<Mutex<String>>,
}

impl TestIdp {
    /// Fija el ID token que devolverá la próxima llamada a `POST /token`.
    fn set_next_id_token(&self, token: String) {
        *self
            .next_id_token
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = token;
    }
}

async fn spawn_test_idp(jwks: JwkSet) -> TestIdp {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del IdP de prueba");
    let addr = listener.local_addr().expect("addr del IdP de prueba");
    let issuer_url = format!("http://{addr}");

    let next_id_token = Arc::new(Mutex::new(String::new()));
    let state = TestIdpState {
        jwks: Arc::new(jwks),
        issuer_url: issuer_url.clone(),
        next_id_token: next_id_token.clone(),
    };

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(serve_discovery))
        .route("/jwks", get(serve_jwks))
        .route("/token", post(serve_token))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del IdP de prueba");
    });

    TestIdp {
        issuer_url,
        next_id_token,
    }
}

/// Instancia del router de autenticación de este Gateway bajo prueba, ya
/// escuchando en un puerto efímero.
struct GatewayUnderTest {
    addr: SocketAddr,
    session_signing_key: SecretString,
}

async fn spawn_gateway(oidc_issuer_url: &str) -> GatewayUnderTest {
    let oidc_client = OidcClient::discover(
        oidc_issuer_url,
        TEST_CLIENT_ID,
        &SecretString::from("test-client-secret".to_string()),
        TEST_REDIRECT_URI,
    )
    .await
    .expect("discovery contra el IdP de prueba debe funcionar");

    let session_signing_key = SecretString::from("lab-only-not-a-real-secret".to_string());

    // Esta feature no ejercita `usuarios_client`: apunta a una URL de
    // laboratorio que nunca se contacta en estos tests.
    let usuarios_client = UsuariosClient::new(
        "http://ms-usuarios.invalid".to_string(),
        SecretString::from("lab-only-not-a-real-secret".to_string()),
    )
    .expect("cliente de laboratorio hacia ms-usuarios debe construirse");

    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: session_signing_key.clone(),
        session_ttl_secs: 3600,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        usuarios_client: Arc::new(usuarios_client),
    };

    let app = auth_router(state);

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
        session_signing_key,
    }
}

fn http_client_no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("cliente http de prueba")
}

/// Inicia sesión contra `gateway` y devuelve el `state` y el `nonce`
/// capturados del `Location` de la redirección `302` de `GET /auth/login`.
async fn start_login(http: &reqwest::Client, gateway: &GatewayUnderTest) -> (String, String) {
    let response = http
        .get(format!("http://{}/auth/login", gateway.addr))
        .send()
        .await
        .expect("GET /auth/login debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);

    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("debe incluir el header Location")
        .to_str()
        .expect("Location debe ser ASCII válido")
        .to_string();

    let url = url::Url::parse(&location).expect("Location debe ser una URL válida");
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

    let state = params
        .get("state")
        .cloned()
        .expect("la URL de autorización debe incluir el parámetro state");
    let nonce = params
        .get("nonce")
        .cloned()
        .expect("la URL de autorización debe incluir el parámetro nonce");

    (state, nonce)
}

#[tokio::test]
async fn login_redirects_to_authorization_endpoint_with_oidc_params() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!("http://{}/auth/login", gateway.addr))
        .send()
        .await
        .expect("GET /auth/login debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);

    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("debe incluir el header Location")
        .to_str()
        .expect("Location debe ser ASCII válido")
        .to_string();

    let url = url::Url::parse(&location).expect("Location debe ser una URL válida");
    assert_eq!(url.origin().ascii_serialization(), idp.issuer_url);

    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(params.get("client_id"), Some(&TEST_CLIENT_ID.to_string()));
    assert_eq!(
        params.get("redirect_uri"),
        Some(&TEST_REDIRECT_URI.to_string())
    );
    assert_eq!(params.get("response_type"), Some(&"code".to_string()));
    let scope = params.get("scope").expect("debe incluir scope");
    for expected in ["openid", "email", "profile"] {
        assert!(
            scope.split(' ').any(|s| s == expected),
            "el scope `{scope}` debe incluir `{expected}`"
        );
    }
    assert!(params.contains_key("state"), "debe incluir state anti-CSRF");
}

#[tokio::test]
async fn callback_with_valid_id_token_creates_session() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let (state_value, nonce_value) = start_login(&http, &gateway).await;

    let claims = TestIdTokenClaims {
        iss: &idp.issuer_url,
        aud: TEST_CLIENT_ID,
        sub: "google-sub-123",
        email: "user@example.com",
        name: "Test User",
        exp: now_epoch_secs() + 300,
        iat: now_epoch_secs(),
        nonce: &nonce_value,
    };
    idp.set_next_id_token(sign_id_token(&key, &claims));

    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code&state={state_value}",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("debe emitir Set-Cookie")
        .to_str()
        .expect("Set-Cookie debe ser ASCII válido");

    assert!(set_cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
    assert!(set_cookie.to_lowercase().contains("httponly"));
    assert!(set_cookie.to_lowercase().contains("secure"));
    assert!(set_cookie.to_lowercase().contains("samesite=strict"));

    let token = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("la cookie debe tener un valor");

    let decoding_key = jsonwebtoken::DecodingKey::from_secret(b"lab-only-not-a-real-secret");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[SESSION_AUDIENCE]);
    validation.set_issuer(&[SESSION_ISSUER]);

    #[derive(serde::Deserialize)]
    struct DecodedClaims {
        sub: String,
        email: String,
        name: String,
        exp: u64,
    }

    let decoded = jsonwebtoken::decode::<DecodedClaims>(&token, &decoding_key, &validation)
        .expect("la sesión emitida debe decodificar con la clave/aud/iss de este Gateway");

    assert_eq!(decoded.claims.sub, "google-sub-123");
    assert_eq!(decoded.claims.email, "user@example.com");
    assert_eq!(decoded.claims.name, "Test User");
    assert!(decoded.claims.exp > now_epoch_secs() as u64);

    // El cuerpo de la respuesta y sus headers nunca deben contener el ID
    // token crudo de Google (ver docs/security-scope.md).
    let raw_id_token = idp
        .next_id_token
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let body = response.text().await.expect("debe poder leer el cuerpo");
    assert!(!body.contains(&raw_id_token));

    let _ = gateway.session_signing_key; // usada arriba solo conceptualmente
}

#[tokio::test]
async fn callback_rejects_id_token_with_wrong_audience() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let (state_value, nonce_value) = start_login(&http, &gateway).await;

    let claims = TestIdTokenClaims {
        iss: &idp.issuer_url,
        aud: "some-other-client-id",
        sub: "google-sub-123",
        email: "user@example.com",
        name: "Test User",
        exp: now_epoch_secs() + 300,
        iat: now_epoch_secs(),
        nonce: &nonce_value,
    };
    idp.set_next_id_token(sign_id_token(&key, &claims));

    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code&state={state_value}",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());
}

#[tokio::test]
async fn callback_rejects_expired_id_token() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let (state_value, nonce_value) = start_login(&http, &gateway).await;

    let claims = TestIdTokenClaims {
        iss: &idp.issuer_url,
        aud: TEST_CLIENT_ID,
        sub: "google-sub-123",
        email: "user@example.com",
        name: "Test User",
        exp: now_epoch_secs() - 300,
        iat: now_epoch_secs() - 600,
        nonce: &nonce_value,
    };
    idp.set_next_id_token(sign_id_token(&key, &claims));

    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code&state={state_value}",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());
}

#[tokio::test]
async fn callback_rejects_id_token_with_invalid_signature() {
    let published_key = generate_test_key("test-kid-1");
    // Firmamos con una clave distinta a la publicada en el JWKS, mismo
    // `kid` a propósito: se debe rechazar por firma criptográfica, no solo
    // por no encontrar el `kid`.
    let signing_key = generate_test_key("test-kid-1");

    let idp = spawn_test_idp(JwkSet {
        keys: vec![published_key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let (state_value, nonce_value) = start_login(&http, &gateway).await;

    let claims = TestIdTokenClaims {
        iss: &idp.issuer_url,
        aud: TEST_CLIENT_ID,
        sub: "google-sub-123",
        email: "user@example.com",
        name: "Test User",
        exp: now_epoch_secs() + 300,
        iat: now_epoch_secs(),
        nonce: &nonce_value,
    };
    idp.set_next_id_token(sign_id_token(&signing_key, &claims));

    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code&state={state_value}",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());
}

#[tokio::test]
async fn callback_rejects_missing_state() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());
}

#[tokio::test]
async fn callback_rejects_state_that_does_not_match_any_pending_login() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    // Ni siquiera iniciamos un login: cualquier `state` es "no vigente".
    let response = http
        .get(format!(
            "http://{}/auth/callback?code=irrelevant-code&state=state-que-nunca-se-emitio",
            gateway.addr
        ))
        .send()
        .await
        .expect("GET /auth/callback debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());
}

#[tokio::test]
async fn logout_clears_the_session_cookie() {
    let key = generate_test_key("test-kid-1");
    let idp = spawn_test_idp(JwkSet {
        keys: vec![key.jwk.clone()],
    })
    .await;
    let gateway = spawn_gateway(&idp.issuer_url).await;
    let http = http_client_no_redirects();

    // Simula un navegador que ya tiene la cookie de sesión (como quedaría
    // tras un login exitoso): `CookieJar::remove` solo emite un `Set-Cookie`
    // de borrado para cookies que el request dice tener.
    let response = http
        .post(format!("http://{}/auth/logout", gateway.addr))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}=some-previous-session-token"),
        )
        .send()
        .await
        .expect("POST /auth/logout debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);

    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("logout debe emitir un Set-Cookie de borrado")
        .to_str()
        .expect("Set-Cookie debe ser ASCII válido");

    assert!(set_cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
    assert!(
        set_cookie.to_lowercase().contains("max-age=0")
            || set_cookie.to_lowercase().contains("expires="),
        "el Set-Cookie de logout debe expirar la cookie: {set_cookie}"
    );
}
