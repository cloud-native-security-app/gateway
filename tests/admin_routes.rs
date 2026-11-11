//! Tests de integración de las rutas de administración (feature
//! `admin_realtime_feed`, tarea KAP-09): `GET /api/admin/metrics` y el SSE
//! `GET /api/admin/events`, servidas por el router real de
//! `gateway::api::app_router` detrás de `require_session` + `require_admin`.
//! `ms-usuarios` es un stub local con roles por identidad que el test puede
//! cambiar (para probar la revocación durante un stream abierto) y el
//! agregador usa un reloj manual. No requieren Docker.

use std::pin::Pin;
use std::time::Duration;

use axum::http::StatusCode;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use gateway::domain::Role;
use serde_json::{json, Value};

mod common;

use common::admin_gateway::{cookie_for, event, get_with, spawn_gateway, Gateway};

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

#[tokio::test]
async fn admin_routes_without_a_session_get_401() {
    let gw = spawn_gateway(RECHECK).await;
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, None).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
}

#[tokio::test]
async fn non_admin_gets_403_on_every_admin_route() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("plain-user", "user");
    let cookie = cookie_for("plain-user", Role::User);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response.text().await.unwrap(), "acceso denegado");
    }
}

#[tokio::test]
async fn demoted_admin_with_a_stale_admin_cookie_gets_403() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("ex-admin", "user");
    let cookie = cookie_for("ex-admin", Role::Admin);
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let response = get_with(&gw, path, Some(&cookie)).await;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn unverifiable_role_gets_503() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::INTERNAL_SERVER_ERROR);
    let response = get_with(
        &gw,
        "/api/admin/metrics",
        Some(&cookie_for("admin-1", Role::Admin)),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn admin_gets_the_metrics_snapshot_as_json() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    gw.feed
        .aggregator
        .ingest(&event(1, "auth.login", Some("someone"), None, json!({})));
    gw.feed
        .aggregator
        .ingest(&event(2, "scan.started", None, Some("scan-1"), json!({})));
    gw.feed.aggregator.record_malformed();

    let response = get_with(
        &gw,
        "/api/admin/metrics",
        Some(&cookie_for("admin-1", Role::Admin)),
    )
    .await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["kpis"]["scans_in_flight"], 1);
    assert_eq!(body["kpis"]["active_users"], 1);
    assert_eq!(body["kpis"]["malformed_records"], 1);
    assert_eq!(body["scans_in_flight"][0]["scan_id"], "scan-1");
    assert_eq!(body["scans_in_flight"][0]["status"], "running");
    assert_eq!(body["recent_events"][0]["event_type"], "scan.started");
    assert_eq!(body["window_seconds"], 900);
    assert!(
        !body.to_string().contains("example.com"),
        "el snapshot no contiene correos ni nombres"
    );
}

#[tokio::test]
async fn sse_sends_a_snapshot_first_then_a_delta_for_each_new_event() {
    let gw = spawn_gateway(Duration::from_secs(60)).await;
    gw.set_role("admin-1", "admin");
    gw.feed
        .aggregator
        .ingest(&event(1, "auth.login", Some("early"), None, json!({})));
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;

    let snapshot = sse.expect("snapshot").await;
    assert_eq!(snapshot["kpis"]["active_users"], 1);
    assert_eq!(snapshot["seq"], 1);

    gw.feed.aggregator.ingest(&event(
        2,
        "scan.requested",
        Some("u"),
        Some("scan-9"),
        json!({"target": "198.51.100.4"}),
    ));
    let delta = sse.expect("delta").await;
    assert_eq!(delta["seq"], 2);
    assert_eq!(delta["event"]["event_type"], "scan.requested");
    assert_eq!(
        delta["scan_change"],
        json!({"scan_id": "scan-9", "status": "requested"})
    );
    assert_eq!(delta["kpis"]["scans_in_flight"], 1);
}

#[tokio::test]
async fn sse_refreshes_the_snapshot_on_every_role_revalidation_while_the_admin_stays_admin() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    // Sin eventos de por medio, el siguiente mensaje es el snapshot de la
    // revalidación (la ventana de los KPIs vence sin que llegue ningún evento).
    sse.expect("snapshot").await;
    sse.expect("snapshot").await;
}

#[tokio::test]
async fn sse_closes_after_the_role_is_revoked_on_revalidation() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    gw.set_role("admin-1", "user");

    let closed = loop {
        let (name, data) = sse
            .next()
            .await
            .expect("debe llegar `closed` antes del fin");
        if name == "closed" {
            break data;
        }
        assert_eq!(
            name, "snapshot",
            "solo snapshots de revalidación antes de revocar"
        );
    };
    assert_eq!(closed, json!({"reason": "role_revalidation_failed"}));
    assert!(
        sse.next().await.is_none(),
        "el stream debe terminar tras `closed`"
    );
}

#[tokio::test]
async fn sse_closes_when_the_role_cannot_be_verified() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    *gw.usuarios.fail_with.lock().unwrap() = Some(StatusCode::BAD_GATEWAY);

    loop {
        let (name, _) = sse.next().await.expect("debe cerrarse con `closed`");
        if name == "closed" {
            break;
        }
    }
    assert!(sse.next().await.is_none());
}

#[tokio::test]
async fn sse_closes_when_the_user_disappears_from_ms_usuarios() {
    let gw = spawn_gateway(RECHECK).await;
    gw.set_role("admin-1", "admin");
    let mut sse = SseReader::open(&gw, &cookie_for("admin-1", Role::Admin)).await;
    sse.expect("snapshot").await;

    gw.usuarios.roles.lock().unwrap().remove("admin-1");

    loop {
        let (name, _) = sse.next().await.expect("debe cerrarse con `closed`");
        if name == "closed" {
            break;
        }
    }
    assert!(sse.next().await.is_none());
}
