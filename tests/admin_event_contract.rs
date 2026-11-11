//! Paridad del consumidor con el contrato `security-event.schema.json`
//! (tarea KAP-09): cada ejemplo de `../broker/contracts/examples/security-event/`
//! lo acepta el parser del consumidor y actualiza el agregador, y el veredicto
//! de `event_contract::parse_record` coincide con el del schema real sobre una
//! batería de mutaciones (test diferencial). Así un cambio del schema rompe
//! este build en vez de divergir en silencio: el consumidor no puede embeber
//! el archivo del schema (no existe al construir la imagen de este repo).
//!
//! Los tests leen el checkout hermano `../broker`; si no existe imprimen un
//! aviso y pasan, igual que `tests/security_event_contract.rs`.

use std::path::PathBuf;
use std::sync::Arc;

use gateway::admin::{AdminAggregator, ManualClock};
use gateway::event_contract::parse_record;
use jsonschema::Validator;
use serde_json::{json, Value};

fn broker_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(relative)
}

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

fn examples() -> Option<Vec<(String, Value)>> {
    let dir = broker_path("examples/security-event");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            dir.display()
        );
        return None;
    };
    let mut out: Vec<_> = entries
        .map(|entry| entry.expect("entrada").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("ejemplo legible");
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                serde_json::from_str(&text).expect("ejemplo JSON"),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        out.len(),
        11,
        "el contrato tiene un ejemplo por tipo de evento"
    );
    Some(out)
}

#[test]
fn every_broker_example_is_accepted_by_the_consumer_and_updates_the_aggregator() {
    let Some(examples) = examples() else { return };
    let aggregator = AdminAggregator::new(Arc::new(ManualClock::new(1_800_000_000_000)));
    for (name, example) in &examples {
        let bytes = serde_json::to_vec(example).unwrap();
        let event = parse_record(&bytes)
            .unwrap_or_else(|rejection| panic!("{name} debe aceptarse: {rejection}"));
        aggregator.ingest(&event);
    }
    let snapshot = aggregator.snapshot();
    assert_eq!(
        snapshot.recent_events.len(),
        11,
        "un evento de registro por ejemplo"
    );
    assert_eq!(snapshot.critical_findings.len(), 1);
    assert_eq!(snapshot.kpis.rate_limit_hits, 1);
    assert_eq!(snapshot.kpis.completed_last_window, 1);
    assert_eq!(snapshot.kpis.failed_last_window, 1);
}

/// Mutaciones sobre cada ejemplo; el veredicto de ambos validadores debe ser
/// el mismo (aceptan o rechazan juntos).
fn mutations(example: &Value) -> Vec<(String, Value)> {
    let mut out = vec![("identidad".to_string(), example.clone())];
    let obj = example.as_object().unwrap();
    for key in obj.keys() {
        let mut v = example.clone();
        v.as_object_mut().unwrap().remove(key);
        out.push((format!("sin {key}"), v));
    }
    let mut set = |label: &str, key: &str, value: Value| {
        let mut v = example.clone();
        v[key] = value;
        out.push((label.to_string(), v));
    };
    set("propiedad extra", "extra", json!(1));
    set(
        "event_type desconocido",
        "event_type",
        json!("scan.exploded"),
    );
    set("event_type numérico", "event_type", json!(7));
    set("event_id no uuid", "event_id", json!("not-a-uuid"));
    set(
        "event_id mayúsculas",
        "event_id",
        json!("3F2B8C1E-5D4A-4E7B-9A10-2C6D8E0F1A06"),
    );
    set("source desconocido", "source", json!("other-service"));
    set(
        "occurred_at sin offset",
        "occurred_at",
        json!("2026-11-10T12:00:00"),
    );
    set(
        "occurred_at con fracción",
        "occurred_at",
        json!("2026-11-10T12:00:00.123+02:00"),
    );
    set(
        "occurred_at con espacio",
        "occurred_at",
        json!("2026-11-10 12:00:00Z"),
    );
    set("actor_sub vacío", "actor_sub", json!(""));
    set("actor_sub 128", "actor_sub", json!("a".repeat(128)));
    set("actor_sub 129", "actor_sub", json!("a".repeat(129)));
    set("actor_sub numérico", "actor_sub", json!(5));
    set("scan_id vacío", "scan_id", json!(""));
    set("scan_id 129", "scan_id", json!("s".repeat(129)));
    set("payload no objeto", "payload", json!([]));
    set("payload con extra", "payload", {
        let mut p = example["payload"].clone();
        p["leak"] = json!("x");
        p
    });
    if let Some(payload) = example["payload"].as_object() {
        for key in payload.keys() {
            let mut v = example.clone();
            v["payload"].as_object_mut().unwrap().remove(key);
            out.push((format!("payload sin {key}"), v));
            for (label, bad) in [
                ("null", json!(null)),
                ("texto", json!("zzz")),
                ("negativo", json!(-1)),
                ("cero", json!(0)),
                ("grande", json!(70000)),
                ("objeto vacío", json!({})),
            ] {
                let mut v = example.clone();
                v["payload"][key] = bad;
                out.push((format!("payload.{key} = {label}"), v));
            }
        }
    }
    // Valores concretos por campo de payload.
    let payload_cases: [(&str, Value); 22] = [
        ("target", json!("999.1.1.1")),
        ("target", json!("01.2.3.4")),
        ("target", json!("198.51.100.4")),
        ("target", json!("2001:db8::1")),
        ("target", json!("2001:db8:0:0:0:0:0:1")),
        ("target", json!("::ffff:192.0.2.1")),
        ("target", json!("::")),
        ("target", json!("1:2:3:4:5:6:7::")),
        ("target", json!("example.com")),
        ("cve_id", json!("CVE-1-1")),
        ("cve_id", json!("CVE-2023-123")),
        ("cve_id", json!("CVE-2023-12345")),
        ("severity", json!("low")),
        ("protocol", json!("icmp")),
        ("confidence", json!("guess")),
        ("route", json!("no-slash")),
        ("route", json!("/with?query")),
        ("route", json!("/with space")),
        ("route", json!(format!("/{}", "r".repeat(200)))),
        ("queue", json!("has space")),
        ("reason_code", json!("Upper")),
        ("action", json!("user.role_changed")),
    ];
    for (field, value) in payload_cases {
        let mut v = example.clone();
        if v["payload"].get(field).is_some() {
            v["payload"][field] = value.clone();
            out.push((format!("payload.{field} = {value}"), v));
        }
    }
    // Un payload completo de otro tipo, y un tipo con el payload del anterior.
    let mut v = example.clone();
    v["event_type"] = json!("auth.login");
    out.push(("payload ajeno a auth.login".to_string(), v));
    out
}

#[test]
fn the_consumer_verdict_matches_the_real_schema_on_every_mutation() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let Some(examples) = examples() else { return };
    let mut checked = 0;
    for (name, example) in &examples {
        for (label, candidate) in mutations(example) {
            let schema_says = validator.is_valid(&candidate);
            let consumer_says = parse_record(&serde_json::to_vec(&candidate).unwrap()).is_ok();
            assert_eq!(
                consumer_says, schema_says,
                "divergencia en {name} [{label}]: schema={schema_says}, consumidor={consumer_says}\n{candidate}"
            );
            checked += 1;
        }
    }
    assert!(checked > 300, "la batería debe ser sustancial ({checked})");
}

#[test]
fn non_json_and_non_object_records_are_rejected_without_echoing_the_body() {
    for body in [&b""[..], b"not json", b"[1,2]", b"null", b"\"text\""] {
        let rejection = parse_record(body).expect_err("debe rechazarse");
        let message = rejection.to_string();
        assert!(
            !message.contains("not json"),
            "el mensaje no debe incluir el cuerpo: {message}"
        );
    }
}
