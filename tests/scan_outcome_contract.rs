//! Paridad de contrato de `ScanOutcome` (tarea KAP-07b, `finding-port`): un
//! mensaje `completed` con hallazgos con y sin puerto valida contra
//! `../broker/contracts/scan-outcome.schema.json` y lo acepta, y relaya sin
//! cambios, el tipo del Gateway. Así un cambio del schema rompe este build en
//! vez de divergir en silencio.
//!
//! Lee el checkout hermano `../broker`; si no existe imprime un aviso y pasa,
//! igual que `tests/security_event_contract.rs`.

use std::path::PathBuf;

use gateway::domain::ScanOutcomeEvent;
use jsonschema::Validator;
use serde_json::{json, Value};

fn schema_validator() -> Option<Validator> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/scan-outcome.schema.json");
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

fn finding(extra: Value) -> Value {
    let mut base = json!({
        "id": "CVE-2024-6387", "severity": "high", "description": "d",
        "nse_script": "vulners", "source": "nmap_nse", "references": [],
        "confidence": "version_match", "patch_state": "unpatched"
    });
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

fn completed(findings: Vec<Value>) -> Value {
    json!({
        "status": "completed",
        "correlation_id": "corr-42",
        "result": {
            "host": "192.0.2.10", "ports": [], "vulnerabilities": findings,
            "scanned_at": "2026-11-09T12:30:00+00:00"
        }
    })
}

#[test]
fn findings_with_and_without_port_match_the_broker_schema_and_relay_verbatim() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let message = completed(vec![
        finding(json!({"port": 22, "protocol": "tcp"})),
        finding(json!({"port": 161, "protocol": "udp"})),
        finding(json!({})),
    ]);
    assert!(validator.is_valid(&message), "{message}");
    let event: ScanOutcomeEvent = serde_json::from_value(message.clone()).expect("decodifica");
    assert_eq!(serde_json::to_value(&event).unwrap(), message);
}

#[test]
fn gateway_and_schema_agree_on_null_and_out_of_range_ports() {
    let Some(validator) = schema_validator() else {
        return;
    };
    for (label, extra, schema_ok) in [
        ("null", json!({"port": null, "protocol": null}), true),
        ("70000", json!({"port": 70000, "protocol": "tcp"}), false),
        (
            "protocolo icmp",
            json!({"port": 22, "protocol": "icmp"}),
            false,
        ),
    ] {
        let message = completed(vec![finding(extra)]);
        assert_eq!(validator.is_valid(&message), schema_ok, "schema [{label}]");
        let gateway_ok = serde_json::from_value::<ScanOutcomeEvent>(message)
            .map(|event| event.is_terminal())
            .unwrap_or(false);
        // El Gateway no valida el conjunto cerrado tcp|udp (lo hace el
        // schema aguas arriba); sí rechaza un puerto fuera de u16.
        if label != "protocolo icmp" {
            assert_eq!(gateway_ok, schema_ok, "gateway [{label}]");
        }
    }
}
