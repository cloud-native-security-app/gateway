//! Rutas de administración (feature `admin_realtime_feed`, tarea KAP-09):
//! `GET /api/admin/metrics` (snapshot JSON) y `GET /api/admin/events` (SSE).
//!
//! Son las primeras rutas detrás de [`crate::auth::require_admin`]; el router
//! de [`crate::api`] las monta dentro de `require_session` (capa externa).
//!
//! ## Protocolo SSE de `GET /api/admin/events`
//!
//! | Evento | Datos | Cuándo |
//! |---|---|---|
//! | `snapshot` | [`AdminSnapshot`] | primero; tras un retraso del cliente (lag); y en cada revalidación del rol |
//! | `delta` | [`AdminDelta`] | por cada evento (o registro malformado) nuevo |
//! | `closed` | [`AdminStreamClosed`] | justo antes de cerrar por fallo de revalidación |
//!
//! Más comentarios `: ping` de keep-alive cada 15 s. Snapshot y suscripción
//! se toman de forma atómica ([`crate::admin::AdminAggregator::subscribe_with_snapshot`]),
//! así que el primer `delta` es el siguiente al snapshot (`seq` consecutivo).
//!
//! ## Decisiones de diseño
//!
//! - **Revalidación del rol**: una conexión SSE puede durar horas y el rol de
//!   la sesión es una instantánea. Cada
//!   [`AdminFeed::role_recheck_interval`] (60 s por defecto) el stream llama a
//!   [`verify_admin`] (la misma política fail-closed que `require_admin`); si
//!   el usuario ya no es admin, ya no existe o no se puede verificar, envía
//!   `closed` (con un motivo genérico) y termina.
//! - **Snapshot en cada revalidación**: la ventana de 15 minutos vence sin
//!   que llegue ningún evento, así que los KPIs de un cliente quieto se
//!   desactualizarían; el snapshot periódico los corrige.
//! - **Cliente lento**: si el receptor del `broadcast` se atrasa más que su
//!   capacidad ([`crate::admin::DELTA_CHANNEL_CAPACITY`]) no hay error: se
//!   toma un snapshot nuevo con un receptor nuevo y se sigue.
//! - **Sin PII**: ver [`crate::admin`].

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{middleware, Extension, Json, Router};
use futures_util::stream::{self, Stream};
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::time::{Instant, MissedTickBehavior};
use utoipa::ToSchema;

use crate::admin::{AdminDelta, AdminFeed, AdminSnapshot};
use crate::api::AppState;
use crate::auth::{require_admin, verify_admin};
use crate::domain::Session;
use crate::usuarios_client::UsuariosClient;

/// Cada cuánto el servidor envía un comentario `: ping` para mantener viva la
/// conexión a través de proxies.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
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
pub(crate) async fn admin_metrics(State(state): State<AppState>) -> Json<AdminSnapshot> {
    Json(state.admin_feed.aggregator.snapshot())
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
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    Sse::new(events_stream(
        Arc::clone(&state.admin_feed),
        Arc::clone(&state.usuarios_client),
        session,
    ))
    .keep_alive(KeepAlive::new().interval(KEEP_ALIVE_INTERVAL).text("ping"))
}

struct StreamState {
    feed: Arc<AdminFeed>,
    usuarios: Arc<UsuariosClient>,
    session: Session,
    receiver: broadcast::Receiver<AdminDelta>,
    ticker: tokio::time::Interval,
    /// Eventos ya armados que faltan por enviar, en orden.
    pending: VecDeque<Event>,
    /// `true` tras encolar `closed`: cuando `pending` se vacía, el stream termina.
    closing: bool,
}

fn snapshot_event(snapshot: &AdminSnapshot) -> Event {
    Event::default()
        .event("snapshot")
        .json_data(snapshot)
        .unwrap_or_else(|_| serialization_error_event())
}

fn delta_event(delta: &AdminDelta) -> Event {
    Event::default()
        .event("delta")
        .json_data(delta)
        .unwrap_or_else(|_| serialization_error_event())
}

fn serialization_error_event() -> Event {
    Event::default()
        .event("error")
        .data("no se pudo serializar el evento")
}

/// Construye el stream de un cliente admin. Separada del handler para probar
/// el lag y la revalidación sin pasar por HTTP.
pub(crate) fn events_stream(
    feed: Arc<AdminFeed>,
    usuarios: Arc<UsuariosClient>,
    session: Session,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let (snapshot, receiver) = feed.aggregator.subscribe_with_snapshot();
    let period = feed.role_recheck_interval;
    let mut ticker = tokio::time::interval_at(Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let state = StreamState {
        feed,
        usuarios,
        session,
        receiver,
        ticker,
        pending: VecDeque::from([snapshot_event(&snapshot)]),
        closing: false,
    };

    stream::unfold(state, |mut state| async move {
        loop {
            if let Some(event) = state.pending.pop_front() {
                return Some((Ok(event), state));
            }
            if state.closing {
                return None;
            }
            tokio::select! {
                received = state.receiver.recv() => match received {
                    Ok(delta) => state.pending.push_back(delta_event(&delta)),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::debug!(skipped, "cliente SSE de administración atrasado; se reenvía un snapshot");
                        resync(&mut state);
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                _ = state.ticker.tick() => {
                    match verify_admin(&state.usuarios, &state.session).await {
                        Ok(()) => resync(&mut state),
                        Err(_) => {
                            // `verify_admin` ya loggeó la causa (sin datos personales).
                            let closed = Event::default()
                                .event("closed")
                                .json_data(AdminStreamClosed { reason: CLOSE_REASON })
                                .unwrap_or_else(|_| serialization_error_event());
                            state.pending.push_back(closed);
                            state.closing = true;
                        }
                    }
                }
            }
        }
    })
}

/// Reemplaza el receptor por uno nuevo y encola un snapshot consistente con
/// él (descarta los deltas atrasados, que el snapshot ya refleja).
fn resync(state: &mut StreamState) {
    let (snapshot, receiver) = state.feed.aggregator.subscribe_with_snapshot();
    state.receiver = receiver;
    state.pending.clear();
    state.pending.push_back(snapshot_event(&snapshot));
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use secrecy::SecretString;

    use super::*;
    use crate::admin::{AdminAggregator, ManualClock, DELTA_CHANNEL_CAPACITY};
    use crate::domain::Role;
    use crate::security_events::SecurityEvent;

    fn login(n: u64) -> SecurityEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": format!("00000000-0000-4000-8000-{n:012}"),
            "event_type": "auth.login",
            "occurred_at": "2026-11-10T12:00:00Z",
            "source": "gateway",
            "actor_sub": format!("user-{n}"),
            "payload": {}
        }))
        .unwrap()
    }

    fn admin_session() -> Session {
        Session {
            sub: "admin-1".into(),
            email: "a@example.com".into(),
            name: "A".into(),
            exp: u64::MAX,
            role: Role::Admin,
        }
    }

    #[tokio::test]
    async fn a_lagging_client_gets_a_fresh_snapshot_instead_of_an_error() {
        let aggregator = Arc::new(AdminAggregator::new(Arc::new(ManualClock::new(0))));
        // Intervalo largo: este test no ejerce la revalidación.
        let feed = Arc::new(AdminFeed::new(
            aggregator.clone(),
            Duration::from_secs(3600),
        ));
        let usuarios = Arc::new(
            UsuariosClient::new(
                "http://ms-usuarios.invalid".into(),
                SecretString::from("x".to_string()),
            )
            .unwrap(),
        );
        let mut stream = std::pin::pin!(events_stream(feed, usuarios, admin_session()));

        let first = format!("{:?}", stream.next().await.unwrap().unwrap());
        assert!(first.contains("snapshot"), "{first}");

        // El cliente no lee mientras se desborda el canal.
        for n in 0..(DELTA_CHANNEL_CAPACITY as u64 + 20) {
            aggregator.ingest(&login(n));
        }

        let next = format!("{:?}", stream.next().await.unwrap().unwrap());
        assert!(
            next.contains("snapshot"),
            "tras el lag llega un snapshot: {next}"
        );
        assert!(
            next.contains(&format!("\\\"seq\\\":{}", DELTA_CHANNEL_CAPACITY + 20)),
            "el snapshot refleja todo lo ingerido: {next}"
        );

        aggregator.ingest(&login(10_000));
        let after = format!("{:?}", stream.next().await.unwrap().unwrap());
        assert!(after.contains("delta"), "luego siguen los deltas: {after}");
    }
}
