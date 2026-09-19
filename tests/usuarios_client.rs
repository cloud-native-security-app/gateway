//! Tests de integración de la feature `usuarios_profile_proxy`, capa
//! `usuarios_client`.
//!
//! Ejercen [`gateway::usuarios_client::UsuariosClient`] contra un servidor
//! HTTP de test real (escuchando en un puerto efímero de `127.0.0.1`, nunca
//! una interceptación a nivel de módulo) que implementa el contrato asumido
//! y documentado en `src/usuarios_client.rs` para `ms-usuarios`
//! (`GET`/`PUT /users/me`) — nunca contra `user-service` de producción (ver
//! `docs/verification.md` Nivel 3). No dependen de Docker, por lo que corren
//! en `cargo test` normal, mismo patrón que `tests/oidc_login.rs`.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use gateway::domain::Session;
use gateway::usuarios_client::{
    UsuariosClient, UsuariosClientError, IDENTITY_HEADER_NAME, SERVICE_SECRET_HEADER_NAME,
};
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const LAB_SHARED_SECRET: &str = "lab-only-not-a-real-secret";

fn lab_session() -> Session {
    Session {
        sub: "google-sub-123".to_string(),
        email: "user@example.com".to_string(),
        name: "Test User".to_string(),
        exp: 9_999_999_999,
    }
}

/// Estado del stub de `ms-usuarios` de prueba: qué credencial de servicio
/// exige y qué perfil tiene almacenado en un momento dado.
#[derive(Clone)]
struct StubState {
    expected_secret: String,
    profile: Arc<Mutex<Value>>,
}

fn secret_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(SERVICE_SECRET_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        == Some(expected)
}

async fn get_users_me(
    State(state): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if !secret_matches(&headers, &state.expected_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "credencial de servicio inválida"})),
        );
    }
    if headers.get(IDENTITY_HEADER_NAME).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "falta el header de identidad"})),
        );
    }

    let profile = state
        .profile
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    (StatusCode::OK, Json(profile))
}

async fn put_users_me(
    State(state): State<StubState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !secret_matches(&headers, &state.expected_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "credencial de servicio inválida"})),
        );
    }

    *state
        .profile
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = body.clone();
    (StatusCode::OK, Json(body))
}

/// Levanta el stub de `ms-usuarios` con `expected_secret` como credencial de
/// servicio válida y `initial_profile` como perfil inicial de `GET /users/me`.
async fn spawn_stub(expected_secret: &str, initial_profile: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let state = StubState {
        expected_secret: expected_secret.to_string(),
        profile: Arc::new(Mutex::new(initial_profile)),
    };

    let app = Router::new()
        .route("/users/me", get(get_users_me).put(put_users_me))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

/// Levanta un stub de `ms-usuarios` que responde `500` a toda solicitud a
/// `/users/me`, para simular un 5xx real del servicio.
async fn spawn_failing_stub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    async fn fail() -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    let app = Router::new().route("/users/me", get(fail).put(fail));

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

/// Devuelve una URL base sobre la que no hay ningún servidor escuchando
/// (puerto efímero reservado y liberado de inmediato): conectar contra ella
/// falla rápido con "connection refused", simulando `ms-usuarios` caído sin
/// depender de un timeout largo.
async fn unreachable_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temporal para reservar un puerto libre");
    let addr = listener.local_addr().expect("addr temporal");
    drop(listener);
    format!("http://{addr}")
}

#[tokio::test]
async fn get_profile_happy_path_returns_the_profile_from_ms_usuarios() {
    let profile = json!({
        "sub": "google-sub-123",
        "email": "user@example.com",
        "display_name": "Test User",
    });
    let base_url = spawn_stub(LAB_SHARED_SECRET, profile.clone()).await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let fetched = client
        .get_profile(&lab_session())
        .await
        .expect("debe devolver el perfil del stub");

    assert_eq!(fetched, profile);
}

#[tokio::test]
async fn upsert_profile_happy_path_returns_the_updated_profile() {
    let base_url = spawn_stub(LAB_SHARED_SECRET, json!({})).await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let new_profile = json!({"display_name": "Updated Name"});
    let saved = client
        .upsert_profile(&lab_session(), &new_profile)
        .await
        .expect("debe guardar el perfil en el stub");

    assert_eq!(saved, new_profile);

    let fetched_again = client
        .get_profile(&lab_session())
        .await
        .expect("debe poder releer el perfil recién guardado");
    assert_eq!(fetched_again, new_profile);
}

#[tokio::test]
async fn get_profile_with_wrong_service_credential_is_rejected_as_unexpected_response() {
    let base_url = spawn_stub("correct-secret-lab-only", json!({})).await;
    let client = UsuariosClient::new(
        base_url,
        SecretString::from("wrong-secret-lab-only".to_string()),
    )
    .expect("cliente de laboratorio debe construirse");

    let result = client.get_profile(&lab_session()).await;

    assert!(
        matches!(
            result,
            Err(UsuariosClientError::UnexpectedResponse { status: 401 })
        ),
        "una credencial de servicio incorrecta (401 de ms-usuarios) debe traducirse a UnexpectedResponse{{status: 401}}, obtuve {result:?}"
    );
}

#[tokio::test]
async fn get_profile_when_ms_usuarios_returns_5xx_is_unexpected_response() {
    let base_url = spawn_failing_stub().await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let result = client.get_profile(&lab_session()).await;

    assert!(
        matches!(
            result,
            Err(UsuariosClientError::UnexpectedResponse { status: 500 })
        ),
        "un 5xx de ms-usuarios debe traducirse a UnexpectedResponse{{status: 500}}, obtuve {result:?}"
    );
}

#[tokio::test]
async fn get_profile_when_ms_usuarios_is_unreachable_returns_a_typed_error_without_panicking() {
    let base_url = unreachable_base_url().await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let result = client.get_profile(&lab_session()).await;

    assert!(
        matches!(result, Err(UsuariosClientError::Unreachable)),
        "ms-usuarios caído debe traducirse a UsuariosClientError::Unreachable, obtuve {result:?}"
    );
}

#[tokio::test]
async fn upsert_profile_when_ms_usuarios_is_unreachable_returns_a_typed_error_without_panicking() {
    let base_url = unreachable_base_url().await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let result = client
        .upsert_profile(&lab_session(), &json!({"display_name": "x"}))
        .await;

    assert!(matches!(result, Err(UsuariosClientError::Unreachable)));
}
