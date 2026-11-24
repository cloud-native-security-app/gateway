//! `POST /api/integrations/siem/alerts` (task SR-02): the machine-to-machine
//! route a Wazuh `integratord` custom integration posts alerts to. Each
//! accepted alert becomes one `siem.alert` [`SecurityEvent`] on the Kinesis
//! security-events stream (contract: `broker/contracts/security-event.schema.json`,
//! D-18; route design: `docs/decisions.md` D-23).
//!
//! ## Design
//!
//! - **Off by default, and invisible when off.** The router is only mounted
//!   when `SIEM_INGEST_TOKEN` is set ([`crate::api::app_router_with_siem`]),
//!   so with no token the path does not exist and answers like any unknown
//!   path.
//! - **Bearer token, not a session.** The route sits outside the session
//!   middleware (there is no user) and has no CSRF check (no cookie is ever
//!   read). The token is compared in constant time ([`subtle`]); only its
//!   length can leak, which is acceptable for a random fixed-length secret.
//!   The token is never logged and [`SiemIngest`]'s `Debug` redacts it.
//! - **Order of checks:** token (401) -> rate limit (429) -> body size (413)
//!   -> no-op publisher (503) -> JSON (400) -> alert shape (422) -> publish
//!   (202 / 503). The rate limit
//!   comes after authentication so unauthenticated noise cannot consume the
//!   integration's quota.
//! - **One alert per request.** `integratord` calls the integration script
//!   once per alert; the body is a single Wazuh alert object, not a batch.
//! - **Publish is awaited**, unlike [`crate::security_events::emit`]: the
//!   caller must learn whether the alert was accepted, so the handler uses
//!   [`publish_with_retry`] (the AP-07 policy: 3 attempts, backoff with
//!   jitter) under [`PUBLISH_TIMEOUT`] and answers `503` when it fails, which
//!   lets the integration retry.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::api::FixedWindowLimiter;
use crate::security_events::{
    publish_with_retry, RetryPolicy, SecurityEvent, SecurityEventPublisher, SiemAlertFields,
    MAX_SIEM_AGENT_NAME_CHARS, MAX_SIEM_TEXT_CHARS, PUBLISH_TIMEOUT,
};

/// Path of the ingestion route.
pub const ROUTE_PATH: &str = "/api/integrations/siem/alerts";
/// Largest accepted request body (a Wazuh alert is a few KiB).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Default quota of the route: requests per [`DEFAULT_RATE_LIMIT_WINDOW`].
pub const DEFAULT_RATE_LIMIT_MAX_REQUESTS: u32 = 120;
/// Default rate limit window.
pub const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Fixed limiter key: the route has a single legitimate caller (the Wazuh
/// manager) and behind the ALB the client IP is the balancer's, so a per-IP
/// key would add nothing.
const RATE_LIMIT_KEY: &str = "siem-ingest";

/// State of the SIEM ingestion route: the bearer token, the publisher and the
/// rate limiter.
#[derive(Clone)]
pub struct SiemIngest {
    token: Arc<SecretString>,
    publisher: Arc<dyn SecurityEventPublisher>,
    limiter: Arc<FixedWindowLimiter>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for SiemIngest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemIngest")
            .field("token", &"[REDACTED]")
            .field(
                "limiter",
                &(self.limiter.max_requests(), self.limiter.window()),
            )
            .finish_non_exhaustive()
    }
}

impl SiemIngest {
    /// Builds the route state with an explicit rate limiter.
    pub fn new(
        token: SecretString,
        publisher: Arc<dyn SecurityEventPublisher>,
        limiter: Arc<FixedWindowLimiter>,
    ) -> Self {
        Self {
            token: Arc::new(token),
            publisher,
            limiter,
            retry: RetryPolicy::default(),
        }
    }

    /// Builds the route state accepting `max_requests` alerts per
    /// [`DEFAULT_RATE_LIMIT_WINDOW`] (`SIEM_INGEST_RATE_LIMIT`; the default is
    /// [`DEFAULT_RATE_LIMIT_MAX_REQUESTS`]).
    pub fn with_rate_limit(
        token: SecretString,
        publisher: Arc<dyn SecurityEventPublisher>,
        max_requests: u32,
    ) -> Self {
        Self::new(
            token,
            publisher,
            Arc::new(FixedWindowLimiter::new(
                max_requests,
                DEFAULT_RATE_LIMIT_WINDOW,
            )),
        )
    }

    fn token_matches(&self, presented: &str) -> bool {
        let expected = self.token.expose_secret().as_bytes();
        bool::from(expected.ct_eq(presented.as_bytes()))
    }
}

/// Router with only the ingestion route, ready to be merged into the app
/// router when the feature is on.
pub fn siem_router(ingest: SiemIngest) -> Router {
    Router::new()
        .route(
            ROUTE_PATH,
            post(ingest_alert).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
        )
        .layer(middleware::from_fn_with_state(ingest.clone(), guard))
        .with_state(ingest)
}

/// Bearer token from `Authorization: Bearer <token>` (scheme case-insensitive).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

/// Authentication, then rate limit; runs before the body is read.
async fn guard(State(ingest): State<SiemIngest>, request: Request, next: Next) -> Response {
    let authenticated = bearer_token(request.headers()).is_some_and(|t| ingest.token_matches(t));
    if !authenticated {
        tracing::warn!("siem ingest: request rejected, missing or invalid bearer token");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    if !ingest.limiter.check_and_record(RATE_LIMIT_KEY) {
        tracing::warn!("siem ingest: request rejected by the rate limit");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                ingest.limiter.window().as_secs().max(1).to_string(),
            )],
            Json(json!({ "error": "rate_limited" })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Receives one Wazuh alert and publishes it as a `siem.alert` event.
///
/// The body is a single alert object as `integratord` hands it to a custom
/// integration (`rule`, `agent`, `data`, ...). Only the fields of the
/// contract are kept; the raw log line is never forwarded.
#[utoipa::path(
    post,
    path = "/api/integrations/siem/alerts",
    tag = "siem",
    request_body(
        content = serde_json::Value,
        content_type = "application/json",
        description = "One Wazuh alert object (not a batch). Used fields: rule.id, rule.level (0..15), rule.description, agent.id, agent.name, data.srcip|src_ip, data.dstip|dest_ip, data.alert.signature."
    ),
    responses(
        (status = 202, description = "Alert accepted and published; body is `{\"event_id\": ...}`."),
        (status = 400, description = "The body is not valid JSON."),
        (status = 401, description = "Missing or wrong bearer token; also what an unmounted route answers (feature off, `SIEM_INGEST_TOKEN` unset), like any unknown path."),
        (status = 413, description = "The body is larger than 64 KiB."),
        (status = 422, description = "The alert does not map to the contract (invalid level or ids, missing fields); the body names the field, never the value."),
        (status = 429, description = "Rate limit exceeded; see `Retry-After`."),
        (status = 503, description = "The event could not be published after retries, or no security events stream is configured (`SECURITY_EVENTS_STREAM_NAME` unset); the integration may retry.")
    ),
    security(("siem_bearer" = []))
)]
pub async fn ingest_alert(State(ingest): State<SiemIngest>, body: Bytes) -> Response {
    // With no real stream behind the publisher an alert would be accepted and
    // silently dropped; refuse it instead so the integration retries later.
    if ingest.publisher.discards_events() {
        tracing::error!("siem ingest: alert refused, no security events stream is configured");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "event_stream_not_configured" })),
        )
            .into_response();
    }
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(_) => {
            tracing::warn!("siem ingest: alert rejected, body is not valid JSON");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_json" })),
            )
                .into_response();
        }
    };
    let event = match map_wazuh_alert(&raw) {
        Ok(event) => event,
        Err(field) => {
            tracing::warn!(
                field,
                "siem ingest: alert rejected, it does not map to the contract"
            );
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "invalid_alert", "field": field })),
            )
                .into_response();
        }
    };

    let published = tokio::time::timeout(
        PUBLISH_TIMEOUT,
        publish_with_retry(ingest.publisher.as_ref(), &event, &ingest.retry),
    )
    .await
    .unwrap_or(false);
    if published {
        tracing::info!(event_id = event.event_id(), "siem ingest: alert published");
        (
            StatusCode::ACCEPTED,
            Json(json!({ "event_id": event.event_id() })),
        )
            .into_response()
    } else {
        tracing::error!(
            event_id = event.event_id(),
            "siem ingest: alert could not be published"
        );
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "publish_failed" })),
        )
            .into_response()
    }
}

/// Maps a Wazuh alert to a `siem.alert` event. The error is the name of the
/// first field that is missing or invalid (never its value).
///
/// - `rule.id`: string or integer; must match `^[A-Za-z0-9_.-]{1,64}$`.
/// - `rule.level`: integer 0..=15 (severity is derived, D-18).
/// - `rule.description`, `agent.name`: text, truncated to the contract bounds.
/// - `data.srcip` / `data.src_ip` and `data.dstip` / `data.dest_ip`: the
///   first value that parses as an IP; unparsable values are ignored.
/// - `data.alert.signature`: Suricata signature, when present.
pub fn map_wazuh_alert(raw: &Value) -> Result<SecurityEvent, &'static str> {
    let rule = raw.get("rule").filter(|v| v.is_object()).ok_or("rule")?;
    let rule_id = match rule.get("id") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) if n.is_u64() || n.is_i64() => n.to_string(),
        _ => return Err("rule.id"),
    };
    let rule_level = rule
        .get("level")
        .and_then(Value::as_u64)
        .and_then(|l| u8::try_from(l).ok())
        .filter(|l| *l <= 15)
        .ok_or("rule.level")?;
    let description =
        text(rule.get("description"), MAX_SIEM_TEXT_CHARS).ok_or("rule.description")?;

    let agent = raw.get("agent").filter(|v| v.is_object()).ok_or("agent")?;
    let agent_id = agent.get("id").and_then(Value::as_str).ok_or("agent.id")?;
    let agent_name = text(agent.get("name"), MAX_SIEM_AGENT_NAME_CHARS).ok_or("agent.name")?;

    let data = raw.get("data");
    let signature = text(
        data.and_then(|d| d.get("alert"))
            .and_then(|a| a.get("signature")),
        MAX_SIEM_TEXT_CHARS,
    );

    SecurityEvent::siem_alert(&SiemAlertFields {
        rule_id: &rule_id,
        rule_level,
        description: &description,
        agent_id,
        agent_name: &agent_name,
        src_ip: first_ip(data, &["srcip", "src_ip"]),
        dest_ip: first_ip(data, &["dstip", "dest_ip"]),
        signature: signature.as_deref(),
    })
    .map_err(|invalid| invalid.field)
}

/// Non-blank text cut to `max` characters (never in the middle of a char).
fn text(value: Option<&Value>, max: usize) -> Option<String> {
    let s = value?.as_str()?;
    if s.trim().is_empty() {
        return None;
    }
    Some(s.chars().take(max).collect())
}

fn first_ip(data: Option<&Value>, keys: &[&str]) -> Option<IpAddr> {
    let data = data?;
    keys.iter()
        .filter_map(|key| data.get(*key)?.as_str()?.trim().parse().ok())
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(level: Value) -> Value {
        json!({
            "rule": {"id": 5710, "level": level, "description": "d"},
            "agent": {"id": "000", "name": "manager"},
        })
    }

    #[test]
    fn rule_id_may_be_a_number_and_level_is_strictly_an_integer_in_range() {
        let event = map_wazuh_alert(&alert(json!(15))).expect("valid");
        assert_eq!(event.payload()["rule_id"], "5710");
        assert_eq!(event.partition_key(), "000");
        for bad in [
            json!(16),
            json!(-1),
            json!("5"),
            json!(5.0),
            json!(300),
            Value::Null,
        ] {
            assert_eq!(
                map_wazuh_alert(&alert(bad.clone())).unwrap_err(),
                "rule.level",
                "{bad}"
            );
        }
    }

    #[test]
    fn blank_text_is_rejected_and_the_error_names_the_field_only() {
        let mut a = alert(json!(3));
        a["rule"]["description"] = json!("   ");
        assert_eq!(map_wazuh_alert(&a).unwrap_err(), "rule.description");
        let mut a = alert(json!(3));
        a["agent"]["id"] = json!("a b");
        assert_eq!(map_wazuh_alert(&a).unwrap_err(), "agent.id");
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bEaReR abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
