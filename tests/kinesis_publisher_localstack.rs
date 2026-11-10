//! Test de integración de `KinesisSecurityEventPublisher` (tarea KAP-06)
//! contra un LocalStack real levantado con `testcontainers` (sin mocks, sin
//! cuenta AWS): se crea el stream, se publica con el adaptador, se lee con
//! `GetRecords` y el cuerpo se valida contra el schema del contrato
//! (`../broker/contracts/security-event.schema.json`; si el repo hermano no
//! está, solo se omite la validación del schema).

mod common;

use std::path::PathBuf;

use gateway::kinesis::KinesisSecurityEventPublisher;
use gateway::security_events::{SecurityEvent, SecurityEventError, SecurityEventPublisher};
use serde_json::Value;

const STREAM: &str = "security-events";

fn schema() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/security-event.schema.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).expect("schema JSON")),
        Err(_) => {
            eprintln!(
                "SKIP schema: {} not found (sibling broker checkout absent)",
                path.display()
            );
            None
        }
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishes_an_event_that_reads_back_valid_with_the_expected_partition_key() {
    let localstack = common::LocalStack::start().await;
    localstack.create_stream(STREAM).await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), STREAM.to_string());

    let scan_event = SecurityEvent::scan_requested("user-sub-123", "corr-42", "198.51.100.4")
        .expect("evento válido");
    let login_event = SecurityEvent::auth_login("user-sub-123").expect("evento válido");
    let dlq_event =
        SecurityEvent::message_deadlettered("gateway-scan-outcomes", "malformed_message")
            .expect("evento válido");
    for event in [&scan_event, &login_event, &dlq_event] {
        publisher.publish(event).await.expect("publicar el evento");
    }

    let records = localstack.read_stream(STREAM, 3).await;
    assert_eq!(records.len(), 3, "deben llegar los tres eventos");
    let validator = schema().map(|s| jsonschema::validator_for(&s).expect("schema compila"));
    let expected = [
        (&scan_event, "corr-42"),
        (&login_event, "user-sub-123"),
        (&dlq_event, dlq_event.event_id()),
    ];
    for (record, (event, partition_key)) in records.iter().zip(expected) {
        let body: Value = serde_json::from_slice(record.data().as_ref()).expect("cuerpo JSON");
        assert_eq!(body, serde_json::to_value(event).unwrap());
        assert_eq!(record.partition_key(), Some(partition_key));
        if let Some(validator) = &validator {
            assert!(
                validator.is_valid(&body),
                "no valida contra el schema: {body}"
            );
        }
        let parsed: SecurityEvent = serde_json::from_value(body).expect("deserializa");
        assert_eq!(&parsed, event);
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishing_to_a_missing_stream_yields_publish_failed_without_the_body() {
    let localstack = common::LocalStack::start().await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), "no-existe".into());

    let err = publisher
        .publish(&SecurityEvent::auth_login("user-sub-123").unwrap())
        .await
        .expect_err("un stream inexistente debe fallar");

    assert!(matches!(err, SecurityEventError::PublishFailed(_)));
    assert!(!err.to_string().contains("user-sub-123"));
}
