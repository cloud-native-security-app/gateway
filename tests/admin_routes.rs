//! Tests de integración de las rutas de administración (feature
//! `admin_realtime_feed`, tarea KAP-09): `GET /api/admin/metrics` y el SSE
//! `GET /api/admin/events`, servidas por el router real de
//! `gateway::api::app_router` detrás de `require_session` + `require_admin`.
//! `ms-usuarios` es un stub local con roles por identidad que el test puede
//! cambiar (para probar la revocación durante un stream abierto) y
//! `events-service` es un servidor falso en proceso (feature
//! `admin_feed_proxy`: el gateway solo hace de proxy). No requieren Docker.

use std::pin::Pin;
use std::time::Duration;

use axum::http::StatusCode;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use gateway::domain::Role;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

mod common;

use common::admin_gateway::{
    cookie_for, get_with, spawn_gateway, unreachable_base_url, FakeEventsService, Gateway,
    EVENTS_SECRET,
};

const RECHECK: Duration = Duration::from_millis(250);
const WAIT: Duration = Duration::from_secs(5);

/// Lector mínimo de `text/event-stream`: devuelve `(evento, datos)`, ignorando
/// los comentarios de keep-alive.
struct SseReader {
    stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    buffer: String,
}

impl SseReader {
    async fn open(gw: &Gateway, cookie: &str) -> Self {
        let response = get_with(gw, "/api/admin/events", Some(cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        Self {
            stream: Box::pin(response.bytes_stream()),
            buffer: String::new(),
        }
    }

    /// Siguiente evento, o `None` si el stream terminó.
    async fn next(&mut self) -> Option<(String, Value)> {
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                let mut name = None;
                let mut data = String::new();
                for line in block.lines() {
                    if let Some(rest) = line.strip_prefix("event:") {
                        name = Some(rest.trim().to_string());
                    } else if let Some(rest) = line.strip_prefix("data:") {
                        data.push_str(rest.trim());
                    }
                }
                if let Some(name) = name {
                    return Some((name, serde_json::from_str(&data).unwrap_or(Value::Null)));
                }
                continue; // solo comentario (keep-alive)
            }
            let chunk = tokio::time::timeout(WAIT, self.stream.next())
                .await
                .expect("el stream no debe quedarse mudo")?;
            self.buffer
                .push_str(&String::from_utf8_lossy(&chunk.expect("chunk")));
        }
    }

    async fn expect(&mut self, name: &str) -> Value {
        let (got, data) = self.next().await.expect("el stream no debe terminar aún");
        assert_eq!(got, name, "datos: {data}");
        data
    }
}

/// Gateway con un `events-service` falso vivo y un admin ya registrado.
async fn setup(recheck: Duration) -> (Gateway, FakeEventsService, String) {
    let upstream = FakeEventsService::spawn().await;
    let gw = spawn_gateway(&upstream.base_url(), recheck).await;
    gw.set_role("admin-1", "admin");
    (gw, upstream, cookie_for("admin-1", Role::Admin))
}

const SNAPSHOT: &str = "event: snapshot\ndata: {\"seq\":1,\"kpis\":{\"active_users\":1}}\n\n";
const DELTA: &str =
    "event: delta\ndata: {\"seq\":2,\"event\":{\"event_type\":\"scan.requested\"}}\n\n";

#[tokio::test]
async fn admin_routes_without_a_session_get_401() {
    let (gw, upstream, _) = setup(RECHECK).await;
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, None).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_admin_gets_403_on_every_admin_route_and_never_reaches_events_service() {
    let (gw, upstream, _) = setup(RECHECK).await;
    gw.set_role("plain-user", "user");
    let cookie = cookie_for("plain-user", Role::User);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response.text().await.unwrap(), "acceso denegado");
    }
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn demoted_admin_with_a_stale_admin_cookie_gets_403() {
    let (gw, upstream, _) = setup(RECHECK).await;
    gw.set_role("ex-admin", "user");
    let cookie = cookie_for("ex-admin", Role::Admin);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unverifiable_role_gets_503() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::INTERNAL_SERVER_ERROR);
    let response = get_with(&gw, "/api/admin/metrics", Some(&cookie)).await;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn metrics_forward_the_upstream_body_and_send_the_shared_secret() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    upstream.set_metrics(StatusCode::OK, r#"{"seq":7,"window_seconds":900}"#);

    let response = get_with(&gw, "/api/admin/metrics", Some(&cookie)).await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body, json!({"seq": 7, "window_seconds": 900}));
    assert_eq!(
        upstream.last_secret.lock().unwrap().as_deref(),
        Some(EVENTS_SECRET)
    );
}

#[tokio::test]
async fn metrics_are_503_when_events_service_is_unreachable() {
    let gw = spawn_gateway(&unreachable_base_url().await, RECHECK).await;
    gw.set_role("admin-1", "admin");
    let cookie = cookie_for("admin-1", Role::Admin);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
}

#[tokio::test]
async fn upstream_401_and_5xx_become_a_generic_502_without_leaking_details() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    for status in [StatusCode::UNAUTHORIZED, StatusCode::INTERNAL_SERVER_ERROR] {
        upstream.set_metrics(status, "secret upstream detail");
        let response = get_with(&gw, "/api/admin/metrics", Some(&cookie)).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_GATEWAY,
            "{status}"
        );
        let text = response.text().await.unwrap();
        assert!(!text.contains("secret upstream detail"), "{text}");
        assert!(!text.contains(EVENTS_SECRET), "{text}");
        assert!(!text.contains("127.0.0.1"), "{text}");
    }
}

#[tokio::test]
async fn sse_passes_frames_through_in_order_even_when_a_frame_is_split_across_chunks() {
    let (gw, upstream, cookie) = setup(Duration::from_secs(60)).await;
    let mut sse = SseReader::open(&gw, &cookie).await;

    // El snapshot llega partido en medio del nombre del evento y de la
    // línea en blanco final; el delta llega junto con un comentario.
    upstream.push("event: snap");
    upstream.push("shot\ndata: {\"seq\":1,\"kpis\":{\"active_users\":1}}\n");
    upstream.push("\n");
    upstream.push(": ping\n\n");
    upstream.push(DELTA);

    let snapshot = sse.expect("snapshot").await;
    assert_eq!(snapshot["seq"], 1);
    let delta = sse.expect("delta").await;
    assert_eq!(delta["seq"], 2);
    assert_eq!(
        upstream.last_secret.lock().unwrap().as_deref(),
        Some(EVENTS_SECRET)
    );
}

#[tokio::test]
async fn sse_forwards_only_complete_frames_so_a_partial_frame_is_withheld() {
    let (gw, upstream, cookie) = setup(Duration::from_secs(60)).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;

    upstream.push("event: delta\ndata: {\"seq\":2");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), sse.next())
            .await
            .is_err(),
        "un frame incompleto no debe reenviarse"
    );
    upstream.push("}\n\n");
    assert_eq!(sse.expect("delta").await["seq"], 2);
}

#[tokio::test]
async fn sse_ends_when_the_upstream_stream_ends_without_inventing_events() {
    let (gw, upstream, cookie) = setup(Duration::from_secs(60)).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;

    upstream.end();

    assert!(
        sse.next().await.is_none(),
        "el stream del cliente termina sin `closed` inventado"
    );
}

#[tokio::test]
async fn sse_keeps_passing_frames_while_the_role_stays_admin_across_revalidations() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;

    tokio::time::sleep(RECHECK * 3).await; // varias revalidaciones exitosas
    upstream.push(DELTA);

    assert_eq!(sse.expect("delta").await["seq"], 2);
}

#[tokio::test]
async fn sse_injects_closed_between_complete_frames_and_ends_after_the_role_is_revoked() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;
    // Un frame a medias en el momento de la revocación: no debe mezclarse con `closed`.
    upstream.push("event: delta\ndata: {\"seq\":");

    gw.set_role("admin-1", "user");

    let (name, data) = sse.next().await.expect("debe llegar `closed`");
    assert_eq!(name, "closed");
    assert_eq!(data, json!({"reason": "role_revalidation_failed"}));
    assert!(
        sse.next().await.is_none(),
        "el stream debe terminar tras `closed`"
    );
}

#[tokio::test]
async fn sse_closes_when_the_role_cannot_be_verified() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;

    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::BAD_GATEWAY);

    assert_eq!(sse.next().await.expect("`closed`").0, "closed");
    assert!(sse.next().await.is_none());
}

#[tokio::test]
async fn sse_closes_when_the_user_disappears_from_ms_usuarios() {
    let (gw, upstream, cookie) = setup(RECHECK).await;
    let mut sse = SseReader::open(&gw, &cookie).await;
    upstream.push(SNAPSHOT);
    sse.expect("snapshot").await;

    gw.usuarios.roles.lock().unwrap().remove("admin-1");

    assert_eq!(sse.next().await.expect("`closed`").0, "closed");
    assert!(sse.next().await.is_none());
}
