//! Tests de integración de la feature `admin-role-guard` (KAP-05).
//!
//! Ejercen `gateway::auth::require_admin` sobre un router de prueba con una
//! única ruta `/probe` (todavía no existe ninguna ruta `/api/admin/*`; la
//! añade KAP-09), servido en un puerto efímero con `axum::serve`. El router
//! compone las mismas capas que usará `protected_router`: `require_session`
//! por fuera y `require_admin` por dentro. No requieren Docker.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::get;
use axum::{middleware, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gateway::auth::{
    issue_session_token, require_admin, require_session, SessionValidator, SESSION_COOKIE_NAME,
};
use gateway::domain::{Role, Session};
use secrecy::SecretString;
use tokio::net::TcpListener;

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const OTHER_SIGNING_KEY: &str = "lab-only-some-other-key";

fn validator() -> SessionValidator {
    SessionValidator::new(
        SecretString::from(SESSION_SIGNING_KEY.to_string()),
        SESSION_AUDIENCE.to_string(),
        SESSION_ISSUER.to_string(),
    )
}

async fn probe() -> &'static str {
    "admin-only-content"
}

async fn serve(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor de prueba");
    });
    addr
}

/// Router de prueba con la composición real: sesión por fuera, admin dentro.
async fn spawn_admin_router() -> SocketAddr {
    let app = Router::new()
        .route("/probe", get(probe))
        .layer(middleware::from_fn(require_admin))
        .layer(middleware::from_fn_with_state(validator(), require_session));
    serve(app).await
}

fn session_with(role: Role) -> Session {
    Session {
        sub: "google-sub-123".to_string(),
        email: "user@example.com".to_string(),
        name: "Test User".to_string(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("reloj")
            .as_secs()
            + 3600,
        role,
    }
}

fn token_for(role: Role, signing_key: &str) -> String {
    issue_session_token(
        &session_with(role),
        &SecretString::from(signing_key.to_string()),
        SESSION_AUDIENCE,
        SESSION_ISSUER,
    )
    .expect("debe firmar")
}

async fn get_probe(addr: SocketAddr, cookie_value: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new().get(format!("http://{addr}/probe"));
    if let Some(value) = cookie_value {
        request = request.header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={value}"),
        );
    }
    request.send().await.expect("GET /probe debe responder")
}

#[tokio::test]
async fn admin_session_reaches_the_admin_route() {
    let addr = spawn_admin_router().await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "admin-only-content");
}

#[tokio::test]
async fn validly_signed_user_session_gets_403_without_leaking_role_or_claims() {
    let addr = spawn_admin_router().await;
    let token = token_for(Role::User, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.text().await.unwrap();
    assert_eq!(body, "acceso denegado");
    for leaked in ["user", "admin", "role", "google-sub-123", "example.com"] {
        assert!(!body.contains(leaked), "el 403 no debe filtrar `{leaked}`");
    }
}

#[tokio::test]
async fn missing_session_cookie_gets_401_not_403() {
    let addr = spawn_admin_router().await;

    let response = get_probe(addr, None).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(response.text().await.unwrap(), "sesión inválida o ausente");
}

/// Un JWT con `role: admin` firmado con otra clave (forjado) se rechaza con
/// 401: nunca llega a evaluarse el rol.
#[tokio::test]
async fn forged_admin_token_with_wrong_signing_key_gets_401() {
    let addr = spawn_admin_router().await;
    let forged = token_for(Role::Admin, OTHER_SIGNING_KEY);

    let response = get_probe(addr, Some(&forged)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// Un token legítimo de `user` cuyo payload se reescribe a `role: admin`
/// conservando la firma original se rechaza con 401.
#[tokio::test]
async fn user_token_with_payload_edited_to_admin_gets_401() {
    let addr = spawn_admin_router().await;
    let token = token_for(Role::User, SESSION_SIGNING_KEY);
    let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
    let payload = URL_SAFE_NO_PAD.decode(&parts[1]).expect("payload base64");
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).expect("payload JSON");
    claims["role"] = serde_json::json!("admin");
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let tampered = parts.join(".");

    let response = get_probe(addr, Some(&tampered)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// Un token sin firma (`alg: none`) con `role: admin` se rechaza con 401.
#[tokio::test]
async fn unsigned_alg_none_admin_token_gets_401() {
    let addr = spawn_admin_router().await;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "sub": "s", "email": "e@example.com", "name": "n", "role": "admin",
            "exp": 9_999_999_999u64, "aud": SESSION_AUDIENCE, "iss": SESSION_ISSUER
        }))
        .unwrap(),
    );
    let unsigned = format!("{header}.{payload}.");

    let response = get_probe(addr, Some(&unsigned)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// Ningún header, query ni cookie adicional puede elevar a un `user`.
#[tokio::test]
async fn client_supplied_role_hints_do_not_elevate_a_user() {
    let addr = spawn_admin_router().await;
    let token = token_for(Role::User, SESSION_SIGNING_KEY);

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/probe?role=admin"))
        .header(
            reqwest::header::COOKIE,
            format!("{SESSION_COOKIE_NAME}={token}; role=admin"),
        )
        .header("X-Role", "admin")
        .header("X-Forwarded-Role", "admin")
        .send()
        .await
        .expect("GET /probe debe responder");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

/// Si `require_admin` se monta sin `require_session` (router mal armado) no
/// deja pasar la request: responde 401 en vez de asumir un rol.
#[tokio::test]
async fn require_admin_without_a_session_layer_fails_closed() {
    let app = Router::new()
        .route("/probe", get(probe))
        .layer(middleware::from_fn(require_admin));
    let addr = serve(app).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
