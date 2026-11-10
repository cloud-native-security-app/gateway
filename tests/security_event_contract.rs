//! Paridad de contrato de `SecurityEvent` (tarea KAP-06): cada evento que
//! construye este Gateway valida contra
//! `../broker/contracts/security-event.schema.json`, y los ejemplos de
//! `../broker/contracts/examples/security-event/` se deserializan en el tipo
//! del Gateway. Así un cambio del schema rompe este build en vez de divergir
//! en silencio (ningún servicio depende del crate `broker`).
//!
//! Los tests leen el checkout hermano `../broker` en tiempo de ejecución; si
//! no existe (este repo clonado solo) imprimen un aviso y pasan, igual que
//! `broker/tests/topology_parity.rs` — sin el otro repo no pueden gatear nada.

use std::path::PathBuf;

use gateway::security_events::SecurityEvent;
use jsonschema::Validator;
use serde_json::Value;

fn broker_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(relative)
}

/// Schema compilado del contrato, o `None` (con aviso) si `../broker` falta.
fn schema_validator() -> Option<Validator> {
    let path = broker_path("security-event.schema.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("el schema debe ser JSON válido");
    Some(jsonschema::validator_for(&schema).expect("el schema debe compilar"))
}

fn assert_valid(validator: &Validator, event: &SecurityEvent) {
    let value = serde_json::to_value(event).expect("el evento debe serializar");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| format!("{e} en {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "el evento {} no valida contra el schema: {errors:?}\n{value}",
        event.event_type_str()
    );
}

#[test]
fn every_gateway_constructor_validates_against_the_broker_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let events = [
        SecurityEvent::scan_requested("user-sub-123", "corr-42", "198.51.100.4"),
        SecurityEvent::scan_requested("user-sub-123", "corr-42", "2001:db8::1"),
        SecurityEvent::scan_requested("user-sub-123", "corr-42", "::ffff:192.0.2.1"),
        SecurityEvent::scan_cancelled("user-sub-123", "corr-42"),
        SecurityEvent::auth_login("user-sub-123"),
        SecurityEvent::auth_logout("user-sub-123"),
        SecurityEvent::ratelimit_hit("user-sub-123", "/api/scans", 10, 60),
        SecurityEvent::ratelimit_hit("user-sub-123", "/api/scans?x=1#frag", 10, 60),
        SecurityEvent::message_deadlettered("gateway-scan-outcomes", "malformed_message"),
    ];
    for event in events {
        assert_valid(
            &validator,
            &event.expect("el constructor debe aceptar la entrada"),
        );
    }
}

#[test]
fn schema_rejects_what_the_constructors_refuse_to_build() {
    // Salvaguarda de la prueba anterior: el validador no es permisivo.
    let Some(validator) = schema_validator() else {
        return;
    };
    let invalid = serde_json::json!({
        "event_id": "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a01",
        "event_type": "ratelimit.hit",
        "occurred_at": "2026-11-09T12:30:00Z",
        "source": "gateway",
        "payload": {"route": "/api/scans?x=1", "limit": 10, "window_seconds": 60}
    });
    assert!(!validator.is_valid(&invalid));
}

#[test]
fn broker_examples_deserialize_into_security_event_and_round_trip() {
    let dir = broker_path("examples/security-event");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            dir.display()
        );
        return;
    };
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("entrada legible").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("ejemplo legible");
        let original: Value = serde_json::from_str(&text).expect("ejemplo JSON");
        let event: SecurityEvent = serde_json::from_value(original.clone())
            .unwrap_or_else(|e| panic!("{} no deserializa: {e}", path.display()));
        let again = serde_json::to_value(&event).expect("serializa");
        assert_eq!(
            again,
            original,
            "{} no hace round trip exacto",
            path.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 11,
        "se esperaban al menos los 11 ejemplos del contrato"
    );
}
