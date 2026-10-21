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
    UsuariosClient, UsuariosClientError, FORWARDED_USER_HEADER_NAME, GATEWAY_SECRET_HEADER_NAME,
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
        .get(GATEWAY_SECRET_HEADER_NAME)
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
    if headers.get(FORWARDED_USER_HEADER_NAME).is_none() {
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

/// Stub de `ms-usuarios` que solo implementa `GET /users/me/scans`,
/// devolviendo `history` tal cual (feature `scan_history_and_cancellation`).
async fn spawn_scan_history_stub(expected_secret: &str, history: Value) -> String {
    #[derive(Clone)]
    struct StubState {
        expected_secret: String,
        history: Value,
    }

    async fn get_users_me_scans(
        State(state): State<StubState>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        if !secret_matches(&headers, &state.expected_secret) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "credencial de servicio inválida"})),
            );
        }
        (StatusCode::OK, Json(state.history))
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");

    let state = StubState {
        expected_secret: expected_secret.to_string(),
        history,
    };

    let app = Router::new()
        .route("/users/me/scans", get(get_users_me_scans))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    format!("http://{addr}")
}

#[tokio::test]
async fn list_scan_history_happy_path_returns_the_history_from_ms_usuarios() {
    let history = json!([
        {
            "scan_id": "ms-usuarios-1",
            "user_id": "google-sub-123",
            "target": "192.0.2.10",
            "status": "PENDIENTE",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "scan_id": "ms-usuarios-2",
            "user_id": "google-sub-123",
            "target": "192.0.2.20",
            "status": "COMPLETADO",
            "requested_at": "2024-01-02T00:00:00Z",
            "updated_at": "2024-01-02T01:00:00Z",
        },
    ]);
    let base_url = spawn_scan_history_stub(LAB_SHARED_SECRET, history).await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let entries = client
        .list_scan_history(&lab_session())
        .await
        .expect("debe devolver el histórico del stub");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].scan_id, "ms-usuarios-1");
    assert_eq!(entries[1].scan_id, "ms-usuarios-2");
}

#[tokio::test]
async fn list_scan_history_when_ms_usuarios_is_unreachable_returns_a_typed_error_without_panicking()
{
    let base_url = unreachable_base_url().await;
    let client = UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse");

    let result = client.list_scan_history(&lab_session()).await;

    assert!(matches!(result, Err(UsuariosClientError::Unreachable)));
}

// ---------------------------------------------------------------------------
// Feature `scan-report`: payloads de `PATCH /scans/{id}`, `failure_reason` /
// `CANCELADO` en el histórico y `GET /users/me/scans/{id}/report`.
// ---------------------------------------------------------------------------

use axum::extract::Path as AxumPath;
use axum::routing::patch;
use gateway::domain::ScanResult;
use gateway::usuarios_client::ScanStatus;

/// Cuerpos capturados por [`spawn_patch_recorder`], en orden de llegada.
type RecordedPatches = Arc<Mutex<Vec<(String, Value)>>>;

/// Stub que solo implementa `PATCH /scans/{scan_id}` y registra `(scan_id,
/// cuerpo JSON)` de cada llamada.
async fn spawn_patch_recorder() -> (String, RecordedPatches) {
    let recorded: RecordedPatches = Arc::new(Mutex::new(Vec::new()));

    async fn record(
        AxumPath(scan_id): AxumPath<String>,
        State(recorded): State<RecordedPatches>,
        Json(body): Json<Value>,
    ) -> StatusCode {
        recorded
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push((scan_id, body));
        StatusCode::NO_CONTENT
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");
    let app = Router::new()
        .route("/scans/:scan_id", patch(record))
        .with_state(recorded.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    (format!("http://{addr}"), recorded)
}

fn lab_client(base_url: String) -> UsuariosClient {
    UsuariosClient::new(base_url, SecretString::from(LAB_SHARED_SECRET.to_string()))
        .expect("cliente de laboratorio debe construirse")
}

fn sample_scan_result() -> ScanResult {
    serde_json::from_value(json!({
        "host": "192.0.2.10",
        "ports": [{
            "port": 22, "protocol": "tcp", "state": "open",
            "service": "ssh", "version": null, "cpes": []
        }],
        "vulnerabilities": [],
        "scanned_at": "2024-01-01T00:00:00Z",
    }))
    .expect("resultado de prueba válido")
}

#[tokio::test]
async fn update_scan_status_without_details_sends_only_the_status() {
    let (base_url, recorded) = spawn_patch_recorder().await;

    lab_client(base_url)
        .update_scan_status(&lab_session(), "ms-1", ScanStatus::EnProgreso)
        .await
        .expect("PATCH debe aceptarse");

    let calls = recorded.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![("ms-1".to_string(), json!({"status": "EN_PROGRESO"}))]
    );
}

#[tokio::test]
async fn update_scan_outcome_with_completado_sends_the_full_result() {
    let (base_url, recorded) = spawn_patch_recorder().await;
    let result = sample_scan_result();

    lab_client(base_url)
        .update_scan_outcome(
            &lab_session(),
            "ms-1",
            ScanStatus::Completado,
            Some(&result),
            None,
        )
        .await
        .expect("PATCH debe aceptarse");

    let calls = recorded.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let body = &calls[0].1;
    assert_eq!(body["status"], json!("COMPLETADO"));
    assert_eq!(body["result"], serde_json::to_value(&result).unwrap());
    assert!(body.get("failure_reason").is_none());
}

#[tokio::test]
async fn update_scan_outcome_with_fallido_and_cancelado_sends_the_failure_reason() {
    let (base_url, recorded) = spawn_patch_recorder().await;
    let client = lab_client(base_url);

    client
        .update_scan_outcome(
            &lab_session(),
            "ms-1",
            ScanStatus::Fallido,
            None,
            Some("host inalcanzable"),
        )
        .await
        .expect("PATCH debe aceptarse");
    client
        .update_scan_outcome(
            &lab_session(),
            "ms-2",
            ScanStatus::Cancelado,
            None,
            Some("cancelado por el usuario"),
        )
        .await
        .expect("PATCH debe aceptarse");

    let calls = recorded.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            (
                "ms-1".to_string(),
                json!({"status": "FALLIDO", "failure_reason": "host inalcanzable"})
            ),
            (
                "ms-2".to_string(),
                json!({"status": "CANCELADO", "failure_reason": "cancelado por el usuario"})
            ),
        ]
    );
}

#[tokio::test]
async fn list_scan_history_parses_failure_reason_and_the_cancelado_status() {
    let history = json!([
        {
            "scan_id": "ms-1", "user_id": "u", "target": "192.0.2.10",
            "status": "CANCELADO",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:01:00Z",
            "failure_reason": "cancelado por el usuario",
        },
        {
            "scan_id": "ms-2", "user_id": "u", "target": "192.0.2.20",
            "status": "COMPLETADO",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:01:00Z",
            "failure_reason": null,
        },
        {
            "scan_id": "ms-3", "user_id": "u", "target": "192.0.2.30",
            "status": "PENDIENTE",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:01:00Z",
        },
    ]);
    let base_url = spawn_scan_history_stub(LAB_SHARED_SECRET, history).await;

    let entries = lab_client(base_url)
        .list_scan_history(&lab_session())
        .await
        .expect("debe devolver el histórico");

    assert_eq!(entries[0].status, ScanStatus::Cancelado);
    assert_eq!(
        entries[0].failure_reason.as_deref(),
        Some("cancelado por el usuario")
    );
    assert_eq!(entries[1].failure_reason, None);
    assert_eq!(entries[2].failure_reason, None);
}

/// Stub de `GET /users/me/scans/{scan_id}/report` con una respuesta fija;
/// registra los headers de autenticación recibidos.
async fn spawn_report_stub(
    status: StatusCode,
    body: Value,
) -> (String, Arc<Mutex<Vec<HeaderMap>>>) {
    #[derive(Clone)]
    struct ReportState {
        status: StatusCode,
        body: Value,
        headers: Arc<Mutex<Vec<HeaderMap>>>,
    }

    async fn report(
        State(state): State<ReportState>,
        AxumPath(_scan_id): AxumPath<String>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        state.headers.lock().unwrap().push(headers);
        (state.status, Json(state.body))
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del stub de ms-usuarios");
    let addr = listener.local_addr().expect("addr del stub de ms-usuarios");
    let app = Router::new()
        .route("/users/me/scans/:scan_id/report", get(report))
        .with_state(ReportState {
            status,
            body,
            headers: seen.clone(),
        });
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("servidor del stub de ms-usuarios");
    });

    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn get_scan_report_returns_the_stored_result_and_sends_the_auth_headers() {
    let result = sample_scan_result();
    let (base_url, seen) =
        spawn_report_stub(StatusCode::OK, serde_json::to_value(&result).unwrap()).await;

    let report = lab_client(base_url)
        .get_scan_report(&lab_session(), "ms-1")
        .await
        .expect("200 debe devolver el reporte");

    assert_eq!(report, result);
    let headers = seen.lock().unwrap();
    assert_eq!(headers.len(), 1);
    assert!(secret_matches(&headers[0], LAB_SHARED_SECRET));
    assert!(headers[0].get(FORWARDED_USER_HEADER_NAME).is_some());
}

#[tokio::test]
async fn get_scan_report_maps_404_and_409_to_typed_errors() {
    let (not_found_url, _) =
        spawn_report_stub(StatusCode::NOT_FOUND, json!({"error": "no existe"})).await;
    let (not_ready_url, _) = spawn_report_stub(
        StatusCode::CONFLICT,
        json!({"error": "el reporte del escaneo aún no está disponible"}),
    )
    .await;

    let not_found = lab_client(not_found_url)
        .get_scan_report(&lab_session(), "ms-1")
        .await;
    let not_ready = lab_client(not_ready_url)
        .get_scan_report(&lab_session(), "ms-1")
        .await;

    assert!(matches!(
        not_found,
        Err(UsuariosClientError::ScanReportNotFound)
    ));
    assert!(matches!(
        not_ready,
        Err(UsuariosClientError::ScanReportNotReady)
    ));
}

#[tokio::test]
async fn get_scan_report_maps_other_statuses_and_bad_bodies_and_unreachable() {
    let (server_error_url, _) =
        spawn_report_stub(StatusCode::INTERNAL_SERVER_ERROR, json!({})).await;
    let (malformed_url, _) = spawn_report_stub(StatusCode::OK, json!({"unexpected": true})).await;

    let server_error = lab_client(server_error_url)
        .get_scan_report(&lab_session(), "ms-1")
        .await;
    let malformed = lab_client(malformed_url)
        .get_scan_report(&lab_session(), "ms-1")
        .await;
    let unreachable = lab_client(unreachable_base_url().await)
        .get_scan_report(&lab_session(), "ms-1")
        .await;

    assert!(matches!(
        server_error,
        Err(UsuariosClientError::UnexpectedResponse { status: 500 })
    ));
    assert!(matches!(
        malformed,
        Err(UsuariosClientError::MalformedResponse)
    ));
    assert!(matches!(unreachable, Err(UsuariosClientError::Unreachable)));
}
