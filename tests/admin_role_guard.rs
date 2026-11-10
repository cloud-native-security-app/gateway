//! Tests de integración de la feature `admin-role-guard` (KAP-05).
//!
//! Ejercen `gateway::auth::require_admin` sobre un router de prueba con una
//! única ruta `/probe` (todavía no existe ninguna ruta `/api/admin/*`; la
//! añade KAP-09), servido en un puerto efímero con `axum::serve`. El router
//! compone las mismas capas que usará `protected_router`: `require_session`
//! por fuera y `require_admin` por dentro. No requieren Docker.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{middleware, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gateway::auth::{
    issue_session_token, require_admin, require_session, SessionValidator, SESSION_COOKIE_NAME,
};
use gateway::domain::{Role, Session};
use gateway::usuarios_client::{
    UsuariosClient, UsuariosClientError, FORWARDED_USER_HEADER_NAME, GATEWAY_SECRET_HEADER_NAME,
};
use secrecy::SecretString;
use tokio::net::TcpListener;

const SESSION_AUDIENCE: &str = "gateway-test";
const SESSION_ISSUER: &str = "gateway-test-issuer";
const SESSION_SIGNING_KEY: &str = "lab-only-not-a-real-secret";
const OTHER_SIGNING_KEY: &str = "lab-only-some-other-key";
const USUARIOS_SHARED_SECRET: &str = "lab-only-usuarios-shared-secret";
/// Cuerpo genérico de los 401/403/503: nunca revela rol ni claims.
const BODY_UNAUTHENTICATED: &str = "sesión inválida o ausente";
const BODY_FORBIDDEN: &str = "acceso denegado";
const BODY_UNAVAILABLE: &str = "no se pudo verificar el rol";
/// Timeout corto del cliente en los tests (la verificación real usa el valor
/// por defecto del cliente).
const TEST_ROLE_CHECK_TIMEOUT: Duration = Duration::from_millis(150);

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

/// Comportamiento del stub de `ms-usuarios` (`GET /users/me`).
#[derive(Clone)]
enum UsuariosBehavior {
    /// `200` con el perfil indicado.
    Profile(serde_json::Value),
    /// `200` con el rol que corresponda a la identidad reenviada en
    /// `X-Forwarded-User`; una identidad desconocida recibe `404` (usuario
    /// inexistente). Prueba que el guard reconsulta al sujeto correcto.
    PerIdentity(Vec<(&'static str, serde_json::Value)>),
    /// Responde con ese status de error.
    Status(StatusCode),
    /// Nunca responde (simula un servicio colgado).
    Hang,
}

#[derive(Clone)]
struct UsuariosStub {
    behavior: UsuariosBehavior,
    calls: Arc<AtomicUsize>,
    /// `sub` de la identidad reenviada en cada llamada, en orden de llegada.
    forwarded_subs: Arc<Mutex<Vec<String>>>,
}

/// Extrae el `sub` del JSON `{"sub", "email"}` de `X-Forwarded-User`.
fn forwarded_sub(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(FORWARDED_USER_HEADER_NAME)?.to_str().ok()?;
    let identity: serde_json::Value = serde_json::from_str(raw).ok()?;
    identity.get("sub")?.as_str().map(str::to_string)
}

async fn get_users_me(
    State(stub): State<UsuariosStub>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    stub.calls.fetch_add(1, Ordering::SeqCst);
    if let Some(sub) = forwarded_sub(&headers) {
        stub.forwarded_subs.lock().unwrap().push(sub);
    }
    let secret_ok = headers
        .get(GATEWAY_SECRET_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        == Some(USUARIOS_SHARED_SECRET);
    if !secret_ok {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }
    match &stub.behavior {
        UsuariosBehavior::Profile(profile) => (StatusCode::OK, Json(profile.clone())),
        UsuariosBehavior::PerIdentity(roles) => {
            let profile = forwarded_sub(&headers)
                .and_then(|sub| roles.iter().find(|(known, _)| *known == sub).cloned());
            match profile {
                Some((_, profile)) => (StatusCode::OK, Json(profile)),
                None => (StatusCode::NOT_FOUND, Json(serde_json::json!({}))),
            }
        }
        UsuariosBehavior::Status(status) => (*status, Json(serde_json::json!({}))),
        UsuariosBehavior::Hang => std::future::pending().await,
    }
}

/// Levanta el stub de `ms-usuarios`; devuelve su URL base y el contador de
/// llamadas recibidas.
async fn spawn_usuarios_stub(behavior: UsuariosBehavior) -> (String, Arc<AtomicUsize>) {
    let (url, calls, _subs) = spawn_usuarios_stub_with_subs(behavior).await;
    (url, calls)
}

/// Como [`spawn_usuarios_stub`], y además devuelve los `sub` reenviados en
/// `X-Forwarded-User` en cada llamada.
async fn spawn_usuarios_stub_with_subs(
    behavior: UsuariosBehavior,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let forwarded_subs = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/users/me", get(get_users_me))
        .with_state(UsuariosStub {
            behavior,
            calls: calls.clone(),
            forwarded_subs: forwarded_subs.clone(),
        });
    let addr = serve(app).await;
    (format!("http://{addr}"), calls, forwarded_subs)
}

/// URL de un `ms-usuarios` caído: un puerto que se cerró de inmediato.
async fn unreachable_usuarios_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

fn usuarios_client(base_url: &str) -> Arc<UsuariosClient> {
    Arc::new(
        UsuariosClient::new(
            base_url.to_string(),
            SecretString::from(USUARIOS_SHARED_SECRET.to_string()),
        )
        .expect("cliente de ms-usuarios")
        .with_role_check_timeout(TEST_ROLE_CHECK_TIMEOUT),
    )
}

/// Router de prueba con la composición real: sesión por fuera, admin dentro.
async fn spawn_admin_router(usuarios_base_url: &str) -> SocketAddr {
    let app = Router::new()
        .route("/probe", get(probe))
        .layer(middleware::from_fn_with_state(
            usuarios_client(usuarios_base_url),
            require_admin,
        ))
        .layer(middleware::from_fn_with_state(validator(), require_session));
    serve(app).await
}

fn session_with(role: Role) -> Session {
    session_for("google-sub-123", role)
}

fn session_for(sub: &str, role: Role) -> Session {
    Session {
        sub: sub.to_string(),
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
    token_for_session(&session_with(role), signing_key)
}

fn token_for_session(session: &Session, signing_key: &str) -> String {
    issue_session_token(
        session,
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

/// Asserts de cuerpo genérico: ni rol ni claims se filtran.
async fn assert_generic_body(response: reqwest::Response, expected: &str) {
    let body = response.text().await.unwrap();
    assert_eq!(body, expected);
    for leaked in ["user", "admin", "role", "google-sub-123", "example.com"] {
        assert!(
            !body.contains(leaked),
            "el cuerpo no debe filtrar `{leaked}`"
        );
    }
}

#[tokio::test]
async fn admin_claim_confirmed_by_ms_usuarios_reaches_the_admin_route() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "admin-only-content");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// R1-001: un admin degradado en `ms-usuarios` con un JWT admin todavía
/// vigente ya no accede.
#[tokio::test]
async fn demoted_admin_with_a_still_valid_admin_jwt_gets_403() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "user"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_generic_body(response, BODY_FORBIDDEN).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Fail closed: un perfil sin `role` o con un valor desconocido no confirma
/// a un administrador.
#[tokio::test]
async fn missing_or_unknown_role_in_ms_usuarios_does_not_confirm_admin() {
    for profile in [
        serde_json::json!({"display_name": "x"}),
        serde_json::json!({"role": "superuser"}),
        serde_json::json!({"role": null}),
    ] {
        let (url, _calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(profile)).await;
        let addr = spawn_admin_router(&url).await;
        let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

        let response = get_probe(addr, Some(&token)).await;

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        assert_generic_body(response, BODY_FORBIDDEN).await;
    }
}

/// Fail closed: si `ms-usuarios` no se puede consultar, nunca se permite.
#[tokio::test]
async fn ms_usuarios_error_response_fails_closed_with_503() {
    let (url, _calls) =
        spawn_usuarios_stub(UsuariosBehavior::Status(StatusCode::INTERNAL_SERVER_ERROR)).await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_generic_body(response, BODY_UNAVAILABLE).await;
}

#[tokio::test]
async fn unreachable_ms_usuarios_fails_closed_with_503() {
    let addr = spawn_admin_router(&unreachable_usuarios_url().await).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_generic_body(response, BODY_UNAVAILABLE).await;
}

/// Un `ms-usuarios` colgado no retiene la request más allá del timeout corto
/// del cliente y tampoco deja pasar.
#[tokio::test]
async fn hanging_ms_usuarios_times_out_and_fails_closed_with_503() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Hang).await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = tokio::time::timeout(Duration::from_secs(5), get_probe(addr, Some(&token)))
        .await
        .expect("la request debe terminar por el timeout del cliente");

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_generic_body(response, BODY_UNAVAILABLE).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Un claim `user` se rechaza sin tocar a `ms-usuarios`.
#[tokio::test]
async fn validly_signed_user_session_gets_403_without_calling_ms_usuarios() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::User, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_generic_body(response, BODY_FORBIDDEN).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_session_cookie_gets_401_not_403() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;

    let response = get_probe(addr, None).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_generic_body(response, BODY_UNAUTHENTICATED).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Un JWT con `role: admin` firmado con otra clave (forjado) se rechaza con
/// 401: nunca llega a evaluarse el rol ni a consultarse `ms-usuarios`.
#[tokio::test]
async fn forged_admin_token_with_wrong_signing_key_gets_401() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
    let forged = token_for(Role::Admin, OTHER_SIGNING_KEY);

    let response = get_probe(addr, Some(&forged)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_generic_body(response, BODY_UNAUTHENTICATED).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Un token legítimo de `user` cuyo payload se reescribe a `role: admin`
/// conservando la firma original se rechaza con 401.
#[tokio::test]
async fn user_token_with_payload_edited_to_admin_gets_401() {
    let (url, _calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::User, SESSION_SIGNING_KEY);
    let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
    let payload = URL_SAFE_NO_PAD.decode(&parts[1]).expect("payload base64");
    let mut claims: serde_json::Value = serde_json::from_slice(&payload).expect("payload JSON");
    claims["role"] = serde_json::json!("admin");
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let tampered = parts.join(".");

    let response = get_probe(addr, Some(&tampered)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_generic_body(response, BODY_UNAUTHENTICATED).await;
}

/// Un token sin firma (`alg: none`) con `role: admin` se rechaza con 401.
#[tokio::test]
async fn unsigned_alg_none_admin_token_gets_401() {
    let (url, _calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
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
    assert_generic_body(response, BODY_UNAUTHENTICATED).await;
}

/// Ningún header, query ni cookie adicional puede elevar a un `user`.
#[tokio::test]
async fn client_supplied_role_hints_do_not_elevate_a_user() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let addr = spawn_admin_router(&url).await;
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
    assert_generic_body(response, BODY_FORBIDDEN).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Si `require_admin` se monta sin `require_session` (router mal armado) no
/// deja pasar la request: responde 401 en vez de asumir un rol.
#[tokio::test]
async fn require_admin_without_a_session_layer_fails_closed() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let app = Router::new()
        .route("/probe", get(probe))
        .layer(middleware::from_fn_with_state(
            usuarios_client(&url),
            require_admin,
        ));
    let addr = serve(app).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_generic_body(response, BODY_UNAUTHENTICATED).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Follow-up (a): el guard reenvía la identidad de la propia sesión y el rol
/// que decide es el de ESE sujeto. Con dos admins (según el claim) y roles
/// distintos en `ms-usuarios`, cada uno recibe el veredicto de su identidad.
#[tokio::test]
async fn guard_forwards_the_session_subject_and_decides_per_identity() {
    let (url, calls, forwarded) =
        spawn_usuarios_stub_with_subs(UsuariosBehavior::PerIdentity(vec![
            ("sub-still-admin", serde_json::json!({"role": "admin"})),
            ("sub-demoted", serde_json::json!({"role": "user"})),
        ]))
        .await;
    let addr = spawn_admin_router(&url).await;
    let still_admin = token_for_session(
        &session_for("sub-still-admin", Role::Admin),
        SESSION_SIGNING_KEY,
    );
    let demoted = token_for_session(
        &session_for("sub-demoted", Role::Admin),
        SESSION_SIGNING_KEY,
    );

    let ok = get_probe(addr, Some(&still_admin)).await;
    let denied = get_probe(addr, Some(&demoted)).await;

    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *forwarded.lock().unwrap(),
        vec!["sub-still-admin".to_string(), "sub-demoted".to_string()],
        "cada llamada debe reenviar el sub de la sesión que la causó"
    );
}

/// Follow-up (b): un `404` definitivo de `ms-usuarios` (el usuario ya no
/// existe) no es "no se pudo verificar": es "no es admin", `403`.
#[tokio::test]
async fn user_gone_in_ms_usuarios_gets_403_not_503() {
    let (url, calls) = spawn_usuarios_stub(UsuariosBehavior::Status(StatusCode::NOT_FOUND)).await;
    let addr = spawn_admin_router(&url).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_generic_body(response, BODY_FORBIDDEN).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Follow-up (b): un `401` de `ms-usuarios` (secreto compartido mal
/// configurado) sigue siendo `503` fail-closed, nunca `403`.
#[tokio::test]
async fn rejected_shared_secret_stays_503() {
    let (url, _calls) = spawn_usuarios_stub(UsuariosBehavior::Profile(
        serde_json::json!({"role": "admin"}),
    ))
    .await;
    let wrong_secret_client = Arc::new(
        UsuariosClient::new(url, SecretString::from("otro-secreto".to_string()))
            .expect("cliente de ms-usuarios")
            .with_role_check_timeout(TEST_ROLE_CHECK_TIMEOUT),
    );
    let app = Router::new()
        .route("/probe", get(probe))
        .layer(middleware::from_fn_with_state(
            wrong_secret_client,
            require_admin,
        ))
        .layer(middleware::from_fn_with_state(validator(), require_session));
    let addr = serve(app).await;
    let token = token_for(Role::Admin, SESSION_SIGNING_KEY);

    let response = get_probe(addr, Some(&token)).await;

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_generic_body(response, BODY_UNAVAILABLE).await;
}

/// El tipo de error que sale de `current_role` distingue cada causa (y su
/// `kind()` es lo único que se loggea, sin datos personales).
#[tokio::test]
async fn current_role_classifies_the_user_service_failures() {
    let session = session_with(Role::Admin);
    let cases = [
        (StatusCode::NOT_FOUND, "user_not_found"),
        (StatusCode::UNAUTHORIZED, "misconfigured"),
        (StatusCode::INTERNAL_SERVER_ERROR, "unexpected_status"),
        (StatusCode::BAD_GATEWAY, "unexpected_status"),
    ];
    for (status, expected_kind) in cases {
        let (url, _calls) = spawn_usuarios_stub(UsuariosBehavior::Status(status)).await;
        let error = usuarios_client(&url)
            .current_role(&session)
            .await
            .expect_err("un status de error no confirma el rol");
        assert_eq!(error.kind(), expected_kind, "status {status}");
    }
    let error = usuarios_client(&unreachable_usuarios_url().await)
        .current_role(&session)
        .await
        .expect_err("un servicio caído no confirma el rol");
    assert!(matches!(error, UsuariosClientError::Unreachable));
    assert_eq!(error.kind(), "unreachable");
}
