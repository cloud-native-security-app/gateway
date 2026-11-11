//! Prueba de punta a punta del panel de administración (tarea KAP-09) contra
//! un LocalStack real levantado con `testcontainers` (sin mocks, sin cuenta
//! AWS): el publicador de Kinesis (KAP-06) publica eventos, el consumidor
//! (`AwsRecordsSource` + `SecurityEventConsumer`) los lee con
//! `GetShardIterator(LATEST)` + `GetRecords`, y `GET /api/admin/metrics` del
//! router real los refleja. También entra un registro basura y se cuenta.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_sdk_kinesis::primitives::Blob;
use gateway::admin::{AdminAggregator, AdminFeed, SystemClock};
use gateway::domain::Role;
use gateway::kinesis::KinesisSecurityEventPublisher;
use gateway::kinesis_consumer::{AwsRecordsSource, SecurityEventConsumer};
use gateway::security_events::{SecurityEvent, SecurityEventPublisher};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use common::admin_gateway::{cookie_for, get_with, spawn_gateway_with_feed};

const STREAM: &str = "security-events";

/// Sondea `condition` hasta `timeout`; falla con `what` si no se cumple.
async fn wait_until(what: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "tiempo agotado esperando: {what}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn events_published_to_kinesis_reach_the_admin_metrics_endpoint() {
    let localstack = common::LocalStack::start().await;
    localstack.create_stream(STREAM).await;

    let aggregator = Arc::new(AdminAggregator::new(Arc::new(SystemClock)));
    let feed = Arc::new(AdminFeed::new(aggregator.clone(), Duration::from_secs(60)));
    let gateway = spawn_gateway_with_feed(feed).await;
    gateway.set_role("admin-1", "admin");

    let shutdown = CancellationToken::new();
    let consumer = SecurityEventConsumer::new(
        Arc::new(AwsRecordsSource::from_client(
            localstack.kinesis.clone(),
            STREAM.to_string(),
        )),
        aggregator.clone(),
    );
    let consumer_task = tokio::spawn(consumer.run(shutdown.clone()));

    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), STREAM.to_string());

    // El consumidor arranca en LATEST: lo publicado antes de que tome su
    // iterador no se ve. Se publica una sonda (sin efecto en los KPIs) hasta
    // que aparece en el registro.
    let probe = SecurityEvent::message_deadlettered("readiness-probe", "probe").unwrap();
    let ready_deadline = Instant::now() + Duration::from_secs(30);
    while aggregator.snapshot().recent_events.is_empty() {
        assert!(
            Instant::now() < ready_deadline,
            "el consumidor no quedó listo"
        );
        publisher.publish(&probe).await.expect("publicar la sonda");
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    // Eventos del gateway, publicados con el adaptador real de KAP-06...
    for event in [
        SecurityEvent::auth_login("admin-1"),
        SecurityEvent::scan_requested("admin-1", "scan-e2e", "198.51.100.4"),
        SecurityEvent::ratelimit_hit("admin-1", "/api/scans", 10, 60),
    ] {
        publisher.publish(&event.unwrap()).await.expect("publicar");
    }
    // ...y los de nmap-service, que este repo no produce, como los publicaría
    // ese servicio, más un registro basura.
    let nmap_events = [
        json!({"event_id": "00000000-0000-4000-8000-0000000000a1", "event_type": "scan.started",
               "occurred_at": "2026-11-10T12:00:00Z", "source": "nmap-service",
               "scan_id": "scan-e2e", "payload": {}}),
        json!({"event_id": "00000000-0000-4000-8000-0000000000a2", "event_type": "finding.critical",
               "occurred_at": "2026-11-10T12:00:01Z", "source": "nmap-service", "scan_id": "scan-e2e",
               "payload": {"port": 22, "protocol": "tcp", "cve_id": "CVE-2023-38408",
                           "severity": "critical", "confidence": "confirmed"}}),
        json!({"event_id": "00000000-0000-4000-8000-0000000000a3", "event_type": "scan.completed",
               "occurred_at": "2026-11-10T12:00:02Z", "source": "nmap-service", "scan_id": "scan-e2e",
               "payload": {"duration_ms": 1200, "finding_counts":
                   {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}}}),
    ];
    let mut bodies: Vec<Vec<u8>> = nmap_events
        .iter()
        .map(|event| serde_json::to_vec(event).unwrap())
        .collect();
    bodies.push(b"this is not a security event".to_vec());
    for body in bodies {
        localstack
            .kinesis
            .put_record()
            .stream_name(STREAM)
            .partition_key("scan-e2e")
            .data(Blob::new(body))
            .send()
            .await
            .expect("put_record");
    }

    wait_until(
        "todos los eventos agregados",
        Duration::from_secs(30),
        || {
            let kpis = aggregator.snapshot().kpis;
            kpis.completed_last_window == 1 && kpis.malformed_records == 1
        },
    )
    .await;

    let response = get_with(
        &gateway,
        "/api/admin/metrics",
        Some(&cookie_for("admin-1", Role::Admin)),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let kpis = &body["kpis"];
    assert_eq!(kpis["scans_in_flight"], 0, "el escaneo ya completó: {body}");
    assert_eq!(kpis["completed_last_window"], 1);
    assert_eq!(kpis["failed_last_window"], 0);
    assert_eq!(kpis["failure_rate"], 0.0);
    assert_eq!(kpis["active_users"], 1);
    assert_eq!(kpis["rate_limit_hits"], 1);
    assert_eq!(kpis["malformed_records"], 1);
    assert_eq!(body["critical_findings"][0]["cve_id"], "CVE-2023-38408");
    assert_eq!(body["critical_findings"][0]["scan_id"], "scan-e2e");
    let types: Vec<&str> = body["recent_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    for expected in [
        "auth.login",
        "scan.requested",
        "scan.started",
        "scan.completed",
    ] {
        assert!(types.contains(&expected), "falta {expected} en {types:?}");
    }

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), consumer_task)
        .await
        .expect("el consumidor debe detenerse")
        .expect("sin panic");
}
