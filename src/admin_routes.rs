//! Rutas de administración (feature `admin_realtime_feed`, tarea KAP-09):
//! `GET /api/admin/metrics` (snapshot JSON) y `GET /api/admin/events` (SSE).
//!
//! Desde la feature `admin_feed_proxy` son un proxy hacia `events-service`
//! ([`crate::events_client`]): el gateway conserva la sesión, [`require_admin`]
//! y la revalidación periódica del rol, y nada más. El router de
//! [`crate::api`] las monta dentro de `require_session` (capa externa).
//!
//! ## Protocolo SSE de `GET /api/admin/events`
//!
//! | Evento | Datos | Origen |
//! |---|---|---|
//! | `snapshot` | [`AdminSnapshot`] | `events-service` (primero y de forma periódica) |
//! | `delta` | [`AdminDelta`] | `events-service`, por cada evento nuevo |
//! | `error` | texto | `events-service` |
//! | `closed` | [`AdminStreamClosed`] | **este gateway**, justo antes de cerrar por fallo de revalidación |
//!
//! Más los comentarios `: ping` de keep-alive que emite `events-service`.
//!
//! ## Decisiones de diseño
//!
//! - **Frames completos**: el stream de `events-service` se reenvía frame a
//!   frame ([`FrameBuffer`]); un frame a medias nunca sale hacia el cliente,
//!   de modo que `closed` jamás cae dentro de otro frame.
//! - **Revalidación del rol**: una conexión SSE puede durar horas y el rol de
//!   la sesión es una instantánea. Cada
//!   [`AdminFeed::role_recheck_interval`] (60 s por defecto) el stream llama a
//!   [`verify_admin`] (la misma política fail-closed que `require_admin`); si
//!   el usuario ya no es admin, ya no existe o no se puede verificar, envía
//!   `closed` (motivo genérico) y termina. Si el rol sigue vigente no se
//!   emite nada: los snapshots periódicos los genera `events-service`.
//! - **Fin del upstream**: si `events-service` cierra el stream o falla la
//!   lectura, el stream del cliente termina sin inventar eventos (el front
//!   reconecta y recibe un snapshot nuevo).
//! - **Errores**: inalcanzable o timeout -> `503`; `401`/`5xx`/otros del
//!   upstream -> `502` con mensaje genérico (el detalle solo se loggea).
//! - **Sin PII**: ver [`crate::admin`].

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{middleware, Extension, Router};
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::time::{Instant, MissedTickBehavior};
use utoipa::ToSchema;

#[allow(unused_imports)] // referenciados por la documentación y el OpenAPI
use crate::admin::{AdminDelta, AdminFeed, AdminSnapshot};
use crate::api::AppState;
use crate::auth::{require_admin, verify_admin};
use crate::domain::Session;
use crate::events_client::{EventsClientError, FrameBuffer, UpstreamBytes};
use crate::usuarios_client::UsuariosClient;

/// Motivo (genérico, sin revelar el rol) del evento `closed`.
const CLOSE_REASON: &str = "role_revalidation_failed";

/// Datos del evento SSE `closed`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminStreamClosed {
    /// Motivo del cierre (`role_revalidation_failed`).
    pub reason: &'static str,
}

/// Rutas de administración, ya protegidas por [`require_admin`]. El llamador
/// (`crate::api`) las envuelve además con `require_session`, de modo que el
/// orden es sesión (externa) -> admin (interna) -> handler.
pub fn admin_router(usuarios: Arc<UsuariosClient>) -> Router<AppState> {
    Router::new()
        .route("/api/admin/metrics", get(admin_metrics))
        .route("/api/admin/events", get(admin_events))
        .layer(middleware::from_fn_with_state(usuarios, require_admin))
}

/// Snapshot actual de las métricas de administración.
#[utoipa::path(
    get,
    path = "/api/admin/metrics",
    tag = "admin",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Snapshot de las métricas de administración.", body = AdminSnapshot),
        (status = 401, description = "Sesión ausente, con firma inválida, o expirada."),
        (status = 403, description = "La sesión no es de un administrador vigente."),
        (status = 503, description = "No se pudo verificar el rol contra ms-usuarios.")
    )
)]
pub(crate) async fn admin_metrics(State(state): State<AppState>) -> Response {
    match state.admin_feed.client.metrics().await {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => upstream_error(&err),
    }
}

/// Stream SSE de métricas de administración: `snapshot` primero, después
/// `delta`, con revalidación periódica del rol (ver la documentación del
/// módulo).
#[utoipa::path(
    get,
    path = "/api/admin/events",
    tag = "admin",
    security(("session_cookie" = [])),
    responses(
        (
            status = 200,
            description = "Stream `text/event-stream`. Eventos: `snapshot` (datos: AdminSnapshot), \
                           `delta` (datos: AdminDelta) y `closed` (datos: AdminStreamClosed).",
            content_type = "text/event-stream",
            body = String
        ),
        (status = 401, description = "Sesión ausente, con firma inválida, o expirada."),
        (status = 403, description = "La sesión no es de un administrador vigente."),
        (status = 503, description = "No se pudo verificar el rol contra ms-usuarios.")
    )
)]
pub(crate) async fn admin_events(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Response {
    let upstream = match state.admin_feed.client.open_events().await {
        Ok(upstream) => upstream,
        Err(err) => return upstream_error(&err),
    };
    let stream = events_stream(
        upstream,
        state.admin_feed.role_recheck_interval,
        Arc::clone(&state.usuarios_client),
        session,
    );
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `503` si `events-service` no responde; `502` (genérico) ante cualquier otra
/// respuesta inesperada. El detalle ya se loggeó en el cliente.
fn upstream_error(err: &EventsClientError) -> Response {
    match err {
        EventsClientError::Unreachable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "servicio de eventos no disponible",
        )
            .into_response(),
        EventsClientError::UnexpectedResponse { .. } | EventsClientError::RequestBuild => (
            StatusCode::BAD_GATEWAY,
            "respuesta inválida del servicio de eventos",
        )
            .into_response(),
    }
}

struct StreamState {
    upstream: UpstreamBytes,
    frames: FrameBuffer,
    usuarios: Arc<UsuariosClient>,
    session: Session,
    ticker: tokio::time::Interval,
    /// Frames completos que faltan por enviar, en orden.
    pending: VecDeque<Bytes>,
    /// `true` tras encolar `closed`: cuando `pending` se vacía, el stream termina.
    closing: bool,
}

fn closed_frame() -> Bytes {
    let data = serde_json::to_string(&AdminStreamClosed {
        reason: CLOSE_REASON,
    })
    .unwrap_or_else(|_| "{}".to_string());
    Bytes::from(format!("event: closed\ndata: {data}\n\n"))
}

/// Reenvía `upstream` frame a frame e inyecta `closed` (y termina) cuando la
/// revalidación del rol falla. Separada del handler para probarla sin HTTP.
pub(crate) fn events_stream(
    upstream: UpstreamBytes,
    role_recheck_interval: Duration,
    usuarios: Arc<UsuariosClient>,
    session: Session,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let mut ticker = tokio::time::interval_at(
        Instant::now() + role_recheck_interval,
        role_recheck_interval,
    );
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let state = StreamState {
        upstream,
        frames: FrameBuffer::new(),
        usuarios,
        session,
        ticker,
        pending: VecDeque::new(),
        closing: false,
    };

    stream::unfold(state, |mut state| async move {
        loop {
            if let Some(frame) = state.pending.pop_front() {
                return Some((Ok(frame), state));
            }
            if state.closing {
                return None;
            }
            tokio::select! {
                chunk = state.upstream.next() => match chunk {
                    Some(Ok(bytes)) => state.pending.extend(state.frames.push(&bytes)),
                    Some(Err(_)) | None => {
                        tracing::info!("el stream de events-service terminó; se cierra el del cliente");
                        return None;
                    }
                },
                _ = state.ticker.tick() => {
                    // `verify_admin` ya loggeó la causa (sin datos personales).
                    if verify_admin(&state.usuarios, &state.session).await.is_err() {
                        state.pending.push_back(closed_frame());
                        state.closing = true;
                    }
                }
            }
        }
    })
}
