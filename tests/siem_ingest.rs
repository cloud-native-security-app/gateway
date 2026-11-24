//! Integration tests for `POST /api/integrations/siem/alerts` (task SR-02):
//! the machine-to-machine route a Wazuh `integratord` integration posts
//! alerts to. The route is served by `gateway::siem_ingest::siem_router`
//! over an ephemeral port with an in-memory publisher; the full-router tests
//! (route off, route not accepting a session) use the shared admin harness.
//!
//! Fixtures under `tests/fixtures/wazuh-alert-*.json` are representative
//! samples written from knowledge of the Wazuh alert format, not captured
//! from a live system. No Docker needed.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway::api::ScanSubmissionRateLimiter;
use gateway::domain::Role;
use gateway::security_events::{
    EventSource, EventType, NoopSecurityEventPublisher, RecordingSecurityEventPublisher,
    SecurityEvent, SecurityEventError, SecurityEventPublisher,
};
use gateway::siem_ingest::{siem_router, SiemIngest, MAX_BODY_BYTES, ROUTE_PATH};
use jsonschema::Validator;
use reqwest::StatusCode;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;

mod common;

const TOKEN: &str = "lab-only-siem-ingest-token-0123456789";
const SSHD_FIXTURE: &str = include_str!("fixtures/wazuh-alert-sshd-auth.json");
const SURICATA_FIXTURE: &str = include_str!("fixtures/wazuh-alert-suricata.json");

struct Harness {
    addr: SocketAddr,
    events: Arc<RecordingSecurityEventPublisher>,
}

impl Harness {
    fn url(&self) -> String {
        format!("http://{}{ROUTE_PATH}", self.addr)
    }

    async fn post(&self, token: Option<&str>, body: impl Into<reqwest::Body>) -> reqwest::Response {
        let mut request = reqwest::Client::new().post(self.url()).body(body);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request.send().await.expect("the route must answer")
    }

    async fn post_alert(&self, alert: &Value) -> reqwest::Response {
        self.post(Some(TOKEN), alert.to_string()).await
    }

    fn published(&self) -> Vec<SecurityEvent> {
        self.events.events()
    }
}

async fn serve(ingest: SiemIngest) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, siem_router(ingest))
            .await
            .expect("server");
    });
    addr
}

fn limiter(max: u32) -> Arc<ScanSubmissionRateLimiter> {
    Arc::new(ScanSubmissionRateLimiter::new(max, Duration::from_secs(60)))
}

async fn harness_with_limit(max: u32) -> Harness {
    let events = Arc::new(RecordingSecurityEventPublisher::new());
    let ingest = SiemIngest::new(
        SecretString::from(TOKEN.to_string()),
        events.clone(),
        limiter(max),
    );
    Harness {
        addr: serve(ingest).await,
        events,
    }
}

async fn harness() -> Harness {
    harness_with_limit(10_000).await
}

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture must be JSON")
}

fn alert(level: Value) -> Value {
    json!({
        "rule": {"id": "5710", "level": level, "description": "sshd: attempt to login using a non-existent user"},
        "agent": {"id": "001", "name": "lab-target"},
        "data": {"srcip": "203.0.113.7"}
    })
}

fn schema_validator() -> Option<Validator> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/security-event.schema.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("schema JSON");
    Some(jsonschema::validator_for(&schema).expect("schema compiles"))
}

fn assert_contract(event: &SecurityEvent) {
    let Some(validator) = schema_validator() else {
        return;
    };
    let value = serde_json::to_value(event).expect("serialize");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "event violates the contract: {errors:?}\n{value}"
    );
}

// ---------------------------------------------------------------- auth

#[tokio::test]
async fn missing_or_wrong_token_is_401_and_publishes_nothing() {
    let h = harness().await;
    let body = fixture(SSHD_FIXTURE).to_string();

    let missing = h.post(None, body.clone()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert!(missing.headers().contains_key("www-authenticate"));

    for wrong in ["wrong", "", &format!("{TOKEN}x"), &TOKEN[..TOKEN.len() - 1]] {
        let response = h.post(Some(wrong), body.clone()).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "token {wrong:?}"
        );
    }

    // Same length, one byte different.
    let mut flipped = TOKEN.to_string();
    flipped.replace_range(0..1, "X");
    assert_eq!(
        h.post(Some(&flipped), body.clone()).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // Right token under another scheme.
    let basic = reqwest::Client::new()
        .post(h.url())
        .header("authorization", format!("Basic {TOKEN}"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(basic.status(), StatusCode::UNAUTHORIZED);
    assert!(h.published().is_empty());
}

#[tokio::test]
async fn other_methods_do_not_bypass_the_token() {
    let h = harness().await;
    let response = reqwest::Client::new().get(h.url()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ------------------------------------------------------------ happy path

#[tokio::test]
async fn sshd_fixture_is_accepted_and_published_as_a_contract_valid_event() {
    let h = harness().await;
    let response = h.post(Some(TOKEN), SSHD_FIXTURE).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: Value = response.json().await.unwrap();

    let events = h.published();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(body["event_id"], event.event_id());
    assert_eq!(event.event_type(), EventType::SiemAlert);
    assert_eq!(event.event_type_str(), "siem.alert");
    assert_eq!(event.source(), EventSource::Wazuh);
    assert_eq!(event.partition_key(), "001");
    assert_eq!(event.actor_sub(), None);
    assert_eq!(event.scan_id(), None);
    assert_eq!(
        event.payload(),
        &json!({
            "rule_id": "5710",
            "rule_level": 5,
            "severity": "low",
            "description": "sshd: attempt to login using a non-existent user",
            "agent": {"id": "001", "name": "lab-target"},
            "src_ip": "203.0.113.7"
        })
    );
    let wire = serde_json::to_value(event).unwrap();
    assert_eq!(wire["source"], "wazuh");
    assert!(wire.get("scan_id").is_none() && wire.get("actor_sub").is_none());
    assert_contract(event);
}

#[tokio::test]
async fn suricata_fixture_maps_signature_and_both_ips_and_leaves_the_raw_log_out() {
    let h = harness().await;
    let response = h.post(Some(TOKEN), SURICATA_FIXTURE).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let events = h.published();
    assert_eq!(events.len(), 1);
    let payload = events[0].payload();
    assert_eq!(payload["rule_id"], "86601");
    assert_eq!(payload["rule_level"], 3);
    assert_eq!(payload["severity"], "low");
    assert_eq!(
        payload["description"],
        "Suricata: Alert - ET SCAN Potential SSH Scan"
    );
    assert_eq!(payload["signature"], "ET SCAN Potential SSH Scan");
    assert_eq!(payload["src_ip"], "203.0.113.7");
    assert_eq!(payload["dest_ip"], "198.51.100.4");
    assert_eq!(payload["agent"], json!({"id": "001", "name": "lab-target"}));
    let text = serde_json::to_string(&events[0]).unwrap();
    assert!(!text.contains("full_log") && !text.contains("flow_id"));
    assert_contract(&events[0]);
}

#[tokio::test]
async fn severity_follows_the_d18_bands_at_every_edge() {
    let h = harness().await;
    let cases = [
        (0, "low"),
        (6, "low"),
        (7, "medium"),
        (9, "medium"),
        (10, "high"),
        (12, "high"),
        (13, "critical"),
        (15, "critical"),
    ];
    for (level, _) in cases {
        let response = h.post_alert(&alert(json!(level))).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "level {level}");
    }
    let events = h.published();
    assert_eq!(events.len(), cases.len());
    for (event, (level, severity)) in events.iter().zip(cases) {
        assert_eq!(event.payload()["rule_level"], level);
        assert_eq!(event.payload()["severity"], severity, "level {level}");
        assert_contract(event);
    }
}

#[tokio::test]
async fn ips_that_do_not_parse_are_ignored_and_the_alternate_key_is_used() {
    let h = harness().await;
    let mut a = alert(json!(5));
    a["data"] = json!({"srcip": "not-an-ip", "dstip": "also bad"});
    assert_eq!(h.post_alert(&a).await.status(), StatusCode::ACCEPTED);
    a["data"] = json!({"srcip": "garbage", "src_ip": "2001:db8::1", "dest_ip": "198.51.100.9"});
    assert_eq!(h.post_alert(&a).await.status(), StatusCode::ACCEPTED);

    let events = h.published();
    assert!(events[0].payload().get("src_ip").is_none());
    assert!(events[0].payload().get("dest_ip").is_none());
    assert_eq!(events[1].payload()["src_ip"], "2001:db8:0:0:0:0:0:1");
    assert_eq!(events[1].payload()["dest_ip"], "198.51.100.9");
    for event in &events {
        assert_contract(event);
    }
}

#[tokio::test]
async fn long_multibyte_text_is_truncated_on_a_char_boundary() {
    let h = harness().await;
    let mut a = alert(json!(5));
    a["rule"]["description"] = json!("日".repeat(300));
    a["agent"]["name"] = json!("é".repeat(200));
    a["data"] = json!({"alert": {"signature": "ñ".repeat(400)}});
    assert_eq!(h.post_alert(&a).await.status(), StatusCode::ACCEPTED);

    let events = h.published();
    let payload = events[0].payload();
    assert_eq!(payload["description"], json!("日".repeat(256)));
    assert_eq!(payload["agent"]["name"], json!("é".repeat(128)));
    assert_eq!(payload["signature"], json!("ñ".repeat(256)));
    assert_contract(&events[0]);
}

// ------------------------------------------------------------- rejections

#[tokio::test]
async fn invalid_alerts_are_rejected_without_publishing() {
    let h = harness().await;

    let malformed = h.post(Some(TOKEN), "{not json").await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        h.post(Some(TOKEN), "").await.status(),
        StatusCode::BAD_REQUEST
    );

    let mut cases: Vec<(&str, Value)> = vec![
        ("level 16", alert(json!(16))),
        ("level -1", alert(json!(-1))),
        ("level text", alert(json!("high"))),
        ("level float", alert(json!(5.5))),
        ("level null", alert(Value::Null)),
        ("not an object", json!([1, 2])),
        ("no rule", json!({"agent": {"id": "001", "name": "x"}})),
    ];
    let mut bad_rule_id = alert(json!(5));
    bad_rule_id["rule"]["id"] = json!("bad id!");
    cases.push(("rule id pattern", bad_rule_id));
    let mut long_rule_id = alert(json!(5));
    long_rule_id["rule"]["id"] = json!("1".repeat(65));
    cases.push(("rule id length", long_rule_id));
    let mut bad_agent_id = alert(json!(5));
    bad_agent_id["agent"]["id"] = json!("../etc");
    cases.push(("agent id pattern", bad_agent_id));
    let mut no_agent = alert(json!(5));
    no_agent.as_object_mut().unwrap().remove("agent");
    cases.push(("no agent", no_agent));
    let mut no_name = alert(json!(5));
    no_name["agent"].as_object_mut().unwrap().remove("name");
    cases.push(("no agent name", no_name));
    let mut no_description = alert(json!(5));
    no_description["rule"]
        .as_object_mut()
        .unwrap()
        .remove("description");
    cases.push(("no description", no_description));

    for (name, body) in cases {
        let response = h.post_alert(&body).await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name}"
        );
        let text = response.text().await.unwrap();
        assert!(
            !text.contains("bad id!"),
            "{name}: the response must not echo input"
        );
    }
    assert!(h.published().is_empty());
}

#[tokio::test]
async fn oversize_body_is_413_and_a_wrong_token_still_gets_401_first() {
    let h = harness().await;
    let big = format!("{{\"padding\":\"{}\"}}", "a".repeat(MAX_BODY_BYTES + 1));
    assert_eq!(
        h.post(Some(TOKEN), big.clone()).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        h.post(Some("wrong"), big).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // A body right at the limit is read (and then rejected as an invalid alert, not as too large).
    let at_limit = format!("{{\"padding\":\"{}\"}}", "a".repeat(MAX_BODY_BYTES - 14));
    assert_eq!(at_limit.len(), MAX_BODY_BYTES);
    assert_eq!(
        h.post(Some(TOKEN), at_limit).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(h.published().is_empty());
}

// ------------------------------------------------------------ rate limit

#[tokio::test]
async fn rate_limit_answers_429_after_the_quota_and_only_authenticated_calls_count() {
    let h = harness_with_limit(2).await;

    // Unauthenticated noise must not eat the quota of the real integration.
    for _ in 0..5 {
        assert_eq!(
            h.post(Some("wrong"), SSHD_FIXTURE).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        h.post(Some(TOKEN), SSHD_FIXTURE).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        h.post(Some(TOKEN), SSHD_FIXTURE).await.status(),
        StatusCode::ACCEPTED
    );
    let limited = h.post(Some(TOKEN), SSHD_FIXTURE).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key("retry-after"));
    assert_eq!(h.published().len(), 2);
}

#[tokio::test]
async fn a_configured_rate_limit_is_honored_and_the_default_is_120_per_minute() {
    assert_eq!(gateway::siem_ingest::DEFAULT_RATE_LIMIT_MAX_REQUESTS, 120);
    assert_eq!(
        gateway::siem_ingest::DEFAULT_RATE_LIMIT_WINDOW,
        Duration::from_secs(60)
    );

    let events = Arc::new(RecordingSecurityEventPublisher::new());
    let ingest =
        SiemIngest::with_rate_limit(SecretString::from(TOKEN.to_string()), events.clone(), 3);
    let h = Harness {
        addr: serve(ingest).await,
        events,
    };

    for _ in 0..3 {
        assert_eq!(
            h.post(Some(TOKEN), SSHD_FIXTURE).await.status(),
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        h.post(Some(TOKEN), SSHD_FIXTURE).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(h.published().len(), 3);
}

// --------------------------------------------------------------- publish

struct AlwaysFails(AtomicUsize);

#[async_trait::async_trait]
impl SecurityEventPublisher for AlwaysFails {
    async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(SecurityEventError::PublishFailed(Box::new(
            std::io::Error::other("kinesis down"),
        )))
    }
}

#[tokio::test]
async fn publish_failure_after_retries_is_503() {
    let failing = Arc::new(AlwaysFails(AtomicUsize::new(0)));
    let ingest = SiemIngest::new(
        SecretString::from(TOKEN.to_string()),
        failing.clone(),
        limiter(100),
    );
    let addr = serve(ingest).await;

    let response = reqwest::Client::new()
        .post(format!("http://{addr}{ROUTE_PATH}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(SSHD_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        failing.0.load(Ordering::SeqCst),
        3,
        "the existing retry policy makes 3 attempts"
    );
}

#[tokio::test]
async fn no_real_event_stream_is_503_and_authentication_still_comes_first() {
    let ingest = SiemIngest::new(
        SecretString::from(TOKEN.to_string()),
        Arc::new(NoopSecurityEventPublisher),
        limiter(100),
    );
    let addr = serve(ingest).await;
    let url = format!("http://{addr}{ROUTE_PATH}");
    let client = reqwest::Client::new();

    let response = client
        .post(&url)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(SSHD_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "event_stream_not_configured");

    let unauthenticated = client.post(&url).body(SSHD_FIXTURE).send().await.unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}

// ------------------------------------------------------------ secrecy

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_token_never_reaches_the_logs_or_debug_output() {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let events = Arc::new(RecordingSecurityEventPublisher::new());
    let ingest = SiemIngest::new(SecretString::from(TOKEN.to_string()), events, limiter(1));
    assert!(!format!("{ingest:?}").contains(TOKEN));
    assert!(format!("{ingest:?}").contains("REDACTED"));
    let addr = serve(ingest).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}{ROUTE_PATH}");
    let wrong = "attacker-guess-token-9876543210";
    for token in [wrong, TOKEN, TOKEN, TOKEN] {
        let _ = client
            .post(&url)
            .header("authorization", format!("Bearer {token}"))
            .body(SSHD_FIXTURE)
            .send()
            .await
            .unwrap();
    }

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        !logs.contains(TOKEN),
        "the configured token leaked into the logs"
    );
    assert!(
        !logs.contains(wrong),
        "a presented token leaked into the logs"
    );
}

// ------------------------------------------------- full router behaviour

#[tokio::test]
async fn route_is_indistinguishable_from_a_missing_one_when_the_feature_is_off() {
    let gw =
        common::admin_gateway::spawn_gateway("http://127.0.0.1:1", Duration::from_secs(60)).await;
    let client = reqwest::Client::new();

    for method in [reqwest::Method::POST, reqwest::Method::GET] {
        let on_route = client
            .request(method.clone(), gw.url(ROUTE_PATH))
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(SSHD_FIXTURE)
            .send()
            .await
            .unwrap();
        let missing = client
            .request(
                method.clone(),
                gw.url("/api/integrations/siem/nothing-here"),
            )
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(SSHD_FIXTURE)
            .send()
            .await
            .unwrap();
        assert_eq!(on_route.status(), missing.status(), "{method}");
        assert_eq!(on_route.headers().get("www-authenticate"), None);
        let (mut a, mut b): (Vec<_>, Vec<_>) = (
            on_route
                .headers()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            missing
                .headers()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
        a.sort_by(|x, y| x.0.as_str().cmp(y.0.as_str()));
        b.sort_by(|x, y| x.0.as_str().cmp(y.0.as_str()));
        assert_eq!(a, b, "{method}: headers differ");
        assert_eq!(
            on_route.text().await.unwrap(),
            missing.text().await.unwrap()
        );
    }

    // With a valid (non-admin) session they still match each other. The
    // gateway's catch-all is the session layer, so a missing path answers
    // 401 without a session and 403 for a non-admin one, never 404.
    let cookie = common::admin_gateway::cookie_for("user-1", Role::User);
    let mut statuses = Vec::new();
    for path in [ROUTE_PATH, "/api/integrations/siem/nothing-here"] {
        let response = client
            .post(gw.url(path))
            .header(reqwest::header::COOKIE, &cookie)
            .body(SSHD_FIXTURE)
            .send()
            .await
            .unwrap();
        statuses.push((response.status(), response.text().await.unwrap()));
    }
    assert_eq!(statuses[0], statuses[1]);
}

#[tokio::test]
async fn enabled_route_ignores_the_session_cookie_and_needs_no_session() {
    let events = Arc::new(RecordingSecurityEventPublisher::new());
    let ingest = SiemIngest::new(
        SecretString::from(TOKEN.to_string()),
        events.clone(),
        limiter(100),
    );
    let gw = common::admin_gateway::spawn_gateway_with_siem(
        "http://127.0.0.1:1",
        Duration::from_secs(60),
        Some(ingest),
    )
    .await;
    let client = reqwest::Client::new();
    let admin_cookie = common::admin_gateway::cookie_for("admin-1", Role::Admin);

    // A valid admin session is not a credential for this route.
    let cookie_only = client
        .post(gw.url(ROUTE_PATH))
        .header(reqwest::header::COOKIE, &admin_cookie)
        .body(SSHD_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(cookie_only.status(), StatusCode::UNAUTHORIZED);

    // The bearer token alone (no cookie, no CSRF header) is enough.
    let bearer_only = client
        .post(gw.url(ROUTE_PATH))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(SSHD_FIXTURE)
        .send()
        .await
        .unwrap();
    assert_eq!(bearer_only.status(), StatusCode::ACCEPTED);
    assert_eq!(events.events().len(), 1);
}
