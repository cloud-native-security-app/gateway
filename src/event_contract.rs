//! Validación de un registro del stream `security-events` contra el contrato
//! `broker/contracts/security-event.schema.json` (feature
//! `admin_realtime_feed`, tarea KAP-09).
//!
//! El consumidor ([`crate::kinesis_consumer`]) no confía en lo que lee del
//! stream: otro servicio (o un productor con un bug) puede publicar un
//! registro fuera del contrato, y el panel no debe mostrarlo ni agregarlo.
//!
//! ## Decisiones de diseño
//!
//! - **Validación propia, sin el archivo del schema**: el schema vive en el
//!   repo `broker` y no existe cuando se construye la imagen de este
//!   servicio, así que no se puede embeber con `include_str!`. Las reglas se
//!   codifican aquí (sin crates nuevos: los patrones son simples) y
//!   `tests/admin_event_contract.rs` compara el veredicto de este módulo con
//!   el del schema real sobre los 11 ejemplos y cientos de mutaciones, de modo
//!   que un cambio del schema rompe ese test.
//! - **`occurred_at` solo se valida por patrón**, igual que el schema (que lo
//!   declara así a propósito: `format` es solo una anotación). El agregador
//!   no depende de ese valor.
//! - **Un rechazo nunca incluye el cuerpo ni valores**: solo la regla
//!   incumplida ([`RecordRejection`]), porque el registro podría contener
//!   cualquier cosa.
//! - Un entero con parte decimal (`5.0`) se rechaza aunque JSON Schema lo
//!   acepte como entero: ningún productor lo emite y es la opción más
//!   estricta.

use std::net::Ipv6Addr;
use std::str::FromStr;

use serde_json::{Map, Value};

use crate::security_events::SecurityEvent;

/// Tipos de evento del contrato.
const EVENT_TYPES: [&str; 11] = [
    "scan.requested",
    "scan.cancelled",
    "scan.started",
    "scan.completed",
    "scan.failed",
    "finding.critical",
    "auth.login",
    "auth.logout",
    "ratelimit.hit",
    "message.deadlettered",
    "audit.recorded",
];
const SOURCES: [&str; 3] = ["gateway", "nmap-service", "user-service"];
const ENVELOPE_KEYS: [&str; 7] = [
    "event_id",
    "event_type",
    "occurred_at",
    "source",
    "actor_sub",
    "scan_id",
    "payload",
];
const MAX_ID_CHARS: usize = 128;

/// Por qué se descartó un registro. Nunca lleva el cuerpo ni valores.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordRejection {
    /// El registro no es JSON válido.
    #[error("el registro no es JSON válido")]
    InvalidJson,
    /// El registro es JSON pero incumple el contrato; nombra la regla.
    #[error("el registro incumple el contrato: {0}")]
    Contract(&'static str),
}

/// Decodifica y valida un registro de Kinesis. Devuelve el [`SecurityEvent`]
/// solo si cumple el contrato completo.
pub fn parse_record(bytes: &[u8]) -> Result<SecurityEvent, RecordRejection> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RecordRejection::InvalidJson)?;
    validate(&value).map_err(RecordRejection::Contract)?;
    serde_json::from_value(value).map_err(|_| RecordRejection::Contract("envelope"))
}

/// Valida `value` contra el contrato; el error nombra la regla incumplida.
pub fn validate(value: &Value) -> Result<(), &'static str> {
    let envelope = value.as_object().ok_or("envelope no es un objeto")?;
    if envelope
        .keys()
        .any(|key| !ENVELOPE_KEYS.contains(&key.as_str()))
    {
        return Err("propiedad desconocida en el envelope");
    }
    for required in ["event_id", "event_type", "occurred_at", "source", "payload"] {
        if !envelope.contains_key(required) {
            return Err("falta una propiedad requerida del envelope");
        }
    }
    if !str_of(envelope, "event_id").is_some_and(is_uuid) {
        return Err("event_id");
    }
    let event_type = str_of(envelope, "event_type")
        .filter(|t| EVENT_TYPES.contains(t))
        .ok_or("event_type")?;
    if !str_of(envelope, "occurred_at").is_some_and(is_rfc3339_shape) {
        return Err("occurred_at");
    }
    if !str_of(envelope, "source").is_some_and(|s| SOURCES.contains(&s)) {
        return Err("source");
    }
    for optional_id in ["actor_sub", "scan_id"] {
        if let Some(id) = envelope.get(optional_id) {
            let ok = id
                .as_str()
                .is_some_and(|s| (1..=MAX_ID_CHARS).contains(&s.chars().count()));
            if !ok {
                return Err(if optional_id == "actor_sub" {
                    "actor_sub"
                } else {
                    "scan_id"
                });
            }
        }
    }

    let needs_scan_id = matches!(
        event_type,
        "scan.requested"
            | "scan.cancelled"
            | "scan.started"
            | "scan.completed"
            | "scan.failed"
            | "finding.critical"
    );
    if needs_scan_id && !envelope.contains_key("scan_id") {
        return Err("falta scan_id");
    }
    let needs_actor = matches!(
        event_type,
        "auth.login" | "auth.logout" | "ratelimit.hit" | "audit.recorded"
    );
    if needs_actor && !envelope.contains_key("actor_sub") {
        return Err("falta actor_sub");
    }

    let payload = envelope["payload"].as_object().ok_or("payload")?;
    validate_payload(event_type, payload)
}

fn validate_payload(event_type: &str, payload: &Map<String, Value>) -> Result<(), &'static str> {
    match event_type {
        "scan.requested" => {
            keys(payload, &["target"], &[])?;
            check(payload, "target", is_ip)
        }
        "scan.cancelled" => {
            keys(payload, &[], &["target"])?;
            if payload.contains_key("target") {
                check(payload, "target", is_ip)?;
            }
            Ok(())
        }
        "scan.started" | "auth.login" | "auth.logout" => keys(payload, &[], &[]),
        "scan.completed" => {
            keys(payload, &["duration_ms", "finding_counts"], &[])?;
            uint(payload, "duration_ms", 0, u64::MAX)?;
            let counts = payload["finding_counts"]
                .as_object()
                .ok_or("finding_counts")?;
            let levels = ["critical", "high", "medium", "low", "info", "unknown"];
            keys(counts, &levels, &[])?;
            levels
                .iter()
                .try_for_each(|level| uint(counts, level, 0, u64::MAX))
        }
        "scan.failed" => {
            keys(payload, &["reason_code"], &[])?;
            check(payload, "reason_code", is_reason_code)
        }
        "finding.critical" => {
            keys(
                payload,
                &["port", "protocol", "cve_id", "severity", "confidence"],
                &[],
            )?;
            // `port`/`protocol` son `null` en un hallazgo a nivel de host.
            if !payload["port"].is_null() {
                uint(payload, "port", 0, 65_535)?;
            }
            if !payload["protocol"].is_null() {
                check(payload, "protocol", |s| matches!(s, "tcp" | "udp"))?;
            }
            if !payload["cve_id"].is_null() {
                check(payload, "cve_id", is_cve)?;
            }
            check(payload, "severity", |s| matches!(s, "high" | "critical"))?;
            check(payload, "confidence", |s| {
                matches!(s, "confirmed" | "version_match")
            })
        }
        "ratelimit.hit" => {
            keys(payload, &["route", "limit", "window_seconds"], &[])?;
            check(payload, "route", is_route)?;
            uint(payload, "limit", 1, u64::MAX)?;
            uint(payload, "window_seconds", 1, u64::MAX)
        }
        "message.deadlettered" => {
            keys(payload, &["queue", "reason_code"], &[])?;
            check(payload, "queue", is_queue_name)?;
            check(payload, "reason_code", is_reason_code)
        }
        "audit.recorded" => {
            keys(payload, &["action", "resource_type"], &[])?;
            check(payload, "action", is_dotted_code)?;
            check(payload, "resource_type", is_dotted_code)
        }
        _ => Err("event_type"),
    }
}

/// El objeto tiene todas las claves de `required` y ninguna fuera de
/// `required` + `optional`.
fn keys(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), &'static str> {
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err("falta una propiedad requerida del payload");
    }
    if object
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("propiedad desconocida en el payload");
    }
    Ok(())
}

fn str_of<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str()
}

fn check(
    object: &Map<String, Value>,
    key: &'static str,
    predicate: impl Fn(&str) -> bool,
) -> Result<(), &'static str> {
    if str_of(object, key).is_some_and(predicate) {
        Ok(())
    } else {
        Err(key)
    }
}

fn uint(
    object: &Map<String, Value>,
    key: &'static str,
    min: u64,
    max: u64,
) -> Result<(), &'static str> {
    match object.get(key).and_then(Value::as_u64) {
        Some(n) if (min..=max).contains(&n) => Ok(()),
        _ => Err(key),
    }
}

/// `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(len, group)| group.len() == *len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `^YYYY-MM-DDTHH:MM:SS(\.[0-9]+)?(Z|[+-]HH:MM)$` (solo la forma, como el
/// schema).
fn is_rfc3339_shape(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        b.get(range)
            .is_some_and(|r| r.iter().all(u8::is_ascii_digit))
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(digits(0..4)
        && at(4, b'-')
        && digits(5..7)
        && at(7, b'-')
        && digits(8..10)
        && at(10, b'T')
        && digits(11..13)
        && at(13, b':')
        && digits(14..16)
        && at(16, b':')
        && digits(17..19))
    {
        return false;
    }
    let mut rest = &s[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return false;
        }
        rest = &fraction[n..];
    }
    if rest == "Z" {
        return true;
    }
    let rb = rest.as_bytes();
    rb.len() == 6
        && (rb[0] == b'+' || rb[0] == b'-')
        && rb[1..3].iter().all(u8::is_ascii_digit)
        && rb[3] == b':'
        && rb[4..6].iter().all(u8::is_ascii_digit)
}

/// IPv4 decimal (sin ceros a la izquierda) o IPv6 sin sufijo IPv4 embebido.
fn is_ip(s: &str) -> bool {
    if s.contains(':') {
        !s.contains('.') && !s.contains('%') && Ipv6Addr::from_str(s).is_ok()
    } else {
        std::net::Ipv4Addr::from_str(s).is_ok()
    }
}

/// `^CVE-[0-9]{4}-[0-9]{4,}$`
fn is_cve(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && number.len() >= 4
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// `^/[^?#\s]{0,199}$`
fn is_route(s: &str) -> bool {
    s.strip_prefix('/').is_some_and(|rest| {
        rest.chars().count() <= 199
            && !rest
                .chars()
                .any(|c| c == '?' || c == '#' || c.is_whitespace())
    })
}

/// `^[A-Za-z0-9_-]{1,80}$`
fn is_queue_name(s: &str) -> bool {
    (1..=80).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_code(s: &str, extra: &[u8]) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
}

/// `^[a-z][a-z0-9_]{0,63}$`
fn is_reason_code(s: &str) -> bool {
    is_code(s, b"_")
}

/// `^[a-z][a-z0-9_.]{0,63}$`
fn is_dotted_code(s: &str) -> bool {
    is_code(s, b"_.")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn login() -> Value {
        json!({
            "event_id": "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a06",
            "event_type": "auth.login",
            "occurred_at": "2026-11-09T12:30:00Z",
            "source": "gateway",
            "actor_sub": "user-1",
            "payload": {}
        })
    }

    #[test]
    fn a_valid_envelope_parses_into_a_security_event() {
        let event = parse_record(&serde_json::to_vec(&login()).unwrap()).unwrap();
        assert_eq!(event.event_type_str(), "auth.login");
        assert_eq!(event.actor_sub(), Some("user-1"));
    }

    #[test]
    fn rejection_messages_name_the_rule_not_the_value() {
        let mut bad = login();
        bad["actor_sub"] = json!("SECRET-TOKEN-VALUE".repeat(20));
        let message = parse_record(&serde_json::to_vec(&bad).unwrap())
            .unwrap_err()
            .to_string();
        assert!(message.contains("actor_sub"));
        assert!(!message.contains("SECRET"));
    }

    #[test]
    fn auth_events_require_an_actor_and_scan_events_a_scan_id() {
        let mut no_actor = login();
        no_actor.as_object_mut().unwrap().remove("actor_sub");
        assert!(validate(&no_actor).is_err());

        let mut started = login();
        started["event_type"] = json!("scan.started");
        assert!(validate(&started).is_err(), "falta scan_id");
        started["scan_id"] = json!("scan-1");
        assert!(validate(&started).is_ok());
    }

    #[test]
    fn schema_ip_forms() {
        assert!(is_ip("198.51.100.4"));
        assert!(is_ip("2001:db8::1"));
        assert!(!is_ip("::ffff:192.0.2.1"));
        assert!(!is_ip("01.2.3.4"));
        assert!(!is_ip("example.com"));
    }

    fn finding_critical(port: Value, protocol: Value) -> Value {
        json!({
            "event_id": "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a06",
            "event_type": "finding.critical",
            "occurred_at": "2026-11-09T12:30:00Z",
            "source": "nmap-service",
            "scan_id": "scan-1",
            "payload": {
                "port": port, "protocol": protocol, "cve_id": "CVE-2023-38408",
                "severity": "critical", "confidence": "confirmed"
            }
        })
    }

    #[test]
    fn finding_critical_accepts_null_port_and_protocol_for_host_level_findings() {
        assert!(validate(&finding_critical(json!(22), json!("tcp"))).is_ok());
        assert!(validate(&finding_critical(Value::Null, Value::Null)).is_ok());
        assert!(validate(&finding_critical(Value::Null, json!("udp"))).is_ok());
    }

    #[test]
    fn finding_critical_still_rejects_bad_port_and_protocol() {
        assert!(validate(&finding_critical(json!(70000), json!("tcp"))).is_err());
        assert!(validate(&finding_critical(json!("22"), json!("tcp"))).is_err());
        assert!(validate(&finding_critical(json!(22), json!("icmp"))).is_err());
    }
}
