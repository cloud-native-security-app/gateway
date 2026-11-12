//! Puerto de eventos de seguridad de este Gateway y su tipo de mensaje
//! (feature `security_event_publisher`, tarea KAP-06): hechos inmutables que
//! se publican en el Kinesis Data Stream `security-events` para que el panel
//! de administración (KAP-09) y otros consumidores los lean sin acoplarse a
//! quien los produce. El contrato es
//! `broker/contracts/security-event.schema.json`; los tests de
//! `tests/security_event_contract.rs` validan cada evento emitido contra él.
//!
//! Los adaptadores viven en [`crate::kinesis`] (real) y en este módulo
//! ([`NoopSecurityEventPublisher`], [`RecordingSecurityEventPublisher`]).
//!
//! ## Decisiones de diseño
//!
//! - **Un fallo de publicación nunca llega al negocio**: los puntos de
//!   emisión usan [`emit`], que publica en una tarea `tokio` desacoplada con
//!   un tope de [`PUBLISH_TIMEOUT`] y solo loggea el tipo de evento. Cada
//!   evento se reintenta con backoff exponencial y jitter ([`RetryPolicy`]:
//!   3 intentos de 1,5 s como máximo) dentro de ese tope. La
//!   petición HTTP no espera a Kinesis ni puede fallar por él. El costo es
//!   que un evento puede perderse si el proceso muere antes de que la tarea
//!   corra; es aceptable porque el estado de negocio es la fuente de verdad.
//! - **Los constructores validan el schema**: cada constructor tipado rechaza
//!   con [`InvalidSecurityEvent`] un valor que el schema no aceptaría (largo,
//!   patrón, IP), en vez de emitir un evento inválido. El error nombra el
//!   campo, nunca el valor.
//! - **Nada sensible**: ningún evento lleva credenciales, tokens, correos ni
//!   cuerpos de mensaje; los motivos son códigos cortos.
//! - **Clave de partición**: `scan_id`, si no `actor_sub`, si no `event_id`
//!   ([`SecurityEvent::partition_key`]).

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Tiempo máximo que una tarea de [`emit`] espera a que el adaptador
/// publique antes de soltar el evento.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Máximo de caracteres de `actor_sub` y `scan_id` según el schema.
const MAX_ID_CHARS: usize = 128;
/// Máximo de caracteres de la ruta de `ratelimit.hit` según el schema.
const MAX_ROUTE_CHARS: usize = 200;
/// Máximo de caracteres del nombre de cola de `message.deadlettered`.
const MAX_QUEUE_CHARS: usize = 80;
/// Máximo de caracteres de un `reason_code`.
const MAX_REASON_CODE_CHARS: usize = 64;

/// Tipo de un [`SecurityEvent`]; cubre los 11 valores del contrato aunque
/// este Gateway solo produce algunos (los demás los producen `nmap-service` y
/// `user-service`, y el consumidor del Gateway debe poder leerlos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Un usuario pidió un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.requested")]
    ScanRequested,
    /// Un usuario pidió cancelar un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.cancelled")]
    ScanCancelled,
    /// `nmap-service` empezó un escaneo.
    #[serde(rename = "scan.started")]
    ScanStarted,
    /// `nmap-service` terminó un escaneo.
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    /// `nmap-service` falló un escaneo.
    #[serde(rename = "scan.failed")]
    ScanFailed,
    /// `nmap-service` encontró un hallazgo alto o crítico.
    #[serde(rename = "finding.critical")]
    FindingCritical,
    /// Un usuario completó el login.
    #[serde(rename = "auth.login")]
    AuthLogin,
    /// Un usuario cerró sesión.
    #[serde(rename = "auth.logout")]
    AuthLogout,
    /// Una petición superó el límite de tasa.
    #[serde(rename = "ratelimit.hit")]
    RatelimitHit,
    /// Un mensaje se envió a una dead-letter queue.
    #[serde(rename = "message.deadlettered")]
    MessageDeadlettered,
    /// `user-service` registró una acción de auditoría.
    #[serde(rename = "audit.recorded")]
    AuditRecorded,
}

impl EventType {
    /// Valor del contrato (`scan.requested`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanRequested => "scan.requested",
            Self::ScanCancelled => "scan.cancelled",
            Self::ScanStarted => "scan.started",
            Self::ScanCompleted => "scan.completed",
            Self::ScanFailed => "scan.failed",
            Self::FindingCritical => "finding.critical",
            Self::AuthLogin => "auth.login",
            Self::AuthLogout => "auth.logout",
            Self::RatelimitHit => "ratelimit.hit",
            Self::MessageDeadlettered => "message.deadlettered",
            Self::AuditRecorded => "audit.recorded",
        }
    }
}

/// Servicio que produjo un [`SecurityEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// Este Gateway.
    #[serde(rename = "gateway")]
    Gateway,
    /// `nmap-service`.
    #[serde(rename = "nmap-service")]
    NmapService,
    /// `user-service`.
    #[serde(rename = "user-service")]
    UserService,
}

/// Evento de seguridad inmutable: el sobre del contrato
/// `security-event.schema.json`. Se construye con los constructores tipados
/// (uno por evento que produce este Gateway) o se deserializa de un registro
/// del stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    event_id: String,
    event_type: EventType,
    occurred_at: String,
    source: EventSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    payload: Value,
}

/// Un constructor de [`SecurityEvent`] recibió un valor que el schema
/// rechazaría. Nombra el campo, nunca el valor (podría ser un dato del
/// usuario).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("el evento '{event_type}' tiene un valor inválido en el campo '{field}'")]
pub struct InvalidSecurityEvent {
    /// Tipo del evento que se intentaba construir.
    pub event_type: &'static str,
    /// Campo (del sobre o del `payload`) con el valor inválido.
    pub field: &'static str,
}

/// Errores al publicar un [`SecurityEvent`]. Ninguna variante incluye el
/// cuerpo del evento.
#[derive(Debug, thiserror::Error)]
pub enum SecurityEventError {
    /// El adaptador no pudo entregar el evento al stream. La causa original
    /// se conserva en `source` (solo visible vía la cadena de `source()`).
    #[error("no se pudo publicar el evento de seguridad")]
    PublishFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// No se pudo serializar el evento a JSON.
    #[error("no se pudo serializar el evento de seguridad")]
    SerializationFailed(#[source] serde_json::Error),
}

/// Puerto: "publicar un [`SecurityEvent`]". `AppState` guarda un
/// `Arc<dyn SecurityEventPublisher>` (igual que `ScanRequestPublisher`) para
/// que los tests que no ejercen eventos no necesiten LocalStack.
///
/// Los llamadores del negocio no usan este método directamente sino [`emit`],
/// que garantiza que un fallo nunca afecte la operación.
#[async_trait::async_trait]
pub trait SecurityEventPublisher: Send + Sync {
    /// Publica `event`, devolviendo éxito solo cuando el destino lo aceptó.
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError>;
}

impl SecurityEvent {
    fn new(
        event_type: EventType,
        actor_sub: Option<&str>,
        scan_id: Option<&str>,
        payload: Value,
    ) -> Result<Self, InvalidSecurityEvent> {
        let invalid = |field| InvalidSecurityEvent {
            event_type: event_type.as_str(),
            field,
        };
        if let Some(sub) = actor_sub {
            if !valid_id(sub) {
                return Err(invalid("actor_sub"));
            }
        }
        if let Some(scan) = scan_id {
            if !valid_id(scan) {
                return Err(invalid("scan_id"));
            }
        }
        Ok(Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            occurred_at: now_rfc3339(),
            source: EventSource::Gateway,
            actor_sub: actor_sub.map(str::to_string),
            scan_id: scan_id.map(str::to_string),
            payload,
        })
    }

    /// `scan.requested`: `actor_sub` pidió el escaneo `scan_id` sobre
    /// `target` (IP única) y el Broker lo aceptó.
    pub fn scan_requested(
        actor_sub: &str,
        scan_id: &str,
        target: &str,
    ) -> Result<Self, InvalidSecurityEvent> {
        let ip: IpAddr = target.parse().map_err(|_| InvalidSecurityEvent {
            event_type: EventType::ScanRequested.as_str(),
            field: "target",
        })?;
        Self::new(
            EventType::ScanRequested,
            Some(actor_sub),
            Some(scan_id),
            json!({ "target": schema_safe_ip(ip) }),
        )
    }

    /// `scan.cancelled`: `actor_sub` canceló el escaneo `scan_id` y el Broker
    /// lo aceptó. Sin `target` (es opcional en el schema y el handler de
    /// cancelación no lo conoce).
    pub fn scan_cancelled(actor_sub: &str, scan_id: &str) -> Result<Self, InvalidSecurityEvent> {
        Self::new(
            EventType::ScanCancelled,
            Some(actor_sub),
            Some(scan_id),
            json!({}),
        )
    }

    /// `auth.login`: `actor_sub` completó el login.
    pub fn auth_login(actor_sub: &str) -> Result<Self, InvalidSecurityEvent> {
        Self::new(EventType::AuthLogin, Some(actor_sub), None, json!({}))
    }

    /// `auth.logout`: `actor_sub` cerró sesión.
    pub fn auth_logout(actor_sub: &str) -> Result<Self, InvalidSecurityEvent> {
        Self::new(EventType::AuthLogout, Some(actor_sub), None, json!({}))
    }

    /// `ratelimit.hit`: `actor_sub` superó `limit` peticiones por ventana de
    /// `window_seconds` sobre `route`. La query string y el fragmento de
    /// `route` se descartan.
    pub fn ratelimit_hit(
        actor_sub: &str,
        route: &str,
        limit: u32,
        window_seconds: u64,
    ) -> Result<Self, InvalidSecurityEvent> {
        let invalid = |field| InvalidSecurityEvent {
            event_type: EventType::RatelimitHit.as_str(),
            field,
        };
        let path = route.split(['?', '#']).next().unwrap_or_default();
        let route_ok = path.starts_with('/')
            && path.chars().count() <= MAX_ROUTE_CHARS
            && !path.chars().any(char::is_whitespace);
        if !route_ok {
            return Err(invalid("route"));
        }
        if limit == 0 {
            return Err(invalid("limit"));
        }
        if window_seconds == 0 {
            return Err(invalid("window_seconds"));
        }
        Self::new(
            EventType::RatelimitHit,
            Some(actor_sub),
            None,
            json!({ "route": path, "limit": limit, "window_seconds": window_seconds }),
        )
    }

    /// `message.deadlettered`: un mensaje de la cola `queue` se envió a su
    /// DLQ por `reason_code` (código corto, nunca texto libre). Jamás
    /// incluye el cuerpo del mensaje.
    pub fn message_deadlettered(
        queue: &str,
        reason_code: &str,
    ) -> Result<Self, InvalidSecurityEvent> {
        let invalid = |field| InvalidSecurityEvent {
            event_type: EventType::MessageDeadlettered.as_str(),
            field,
        };
        let queue_ok = (1..=MAX_QUEUE_CHARS).contains(&queue.chars().count())
            && queue
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !queue_ok {
            return Err(invalid("queue"));
        }
        if !valid_reason_code(reason_code) {
            return Err(invalid("reason_code"));
        }
        Self::new(
            EventType::MessageDeadlettered,
            None,
            None,
            json!({ "queue": queue, "reason_code": reason_code }),
        )
    }

    /// UUID v4 único de este evento (los consumidores deduplican por él:
    /// Kinesis entrega al menos una vez).
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Tipo del evento.
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Tipo del evento como texto del contrato.
    pub fn event_type_str(&self) -> &'static str {
        self.event_type.as_str()
    }

    /// Instante del evento, RFC 3339 en UTC.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Servicio que produjo el evento.
    pub fn source(&self) -> EventSource {
        self.source
    }

    /// `sub` del usuario que causó el evento, si aplica.
    pub fn actor_sub(&self) -> Option<&str> {
        self.actor_sub.as_deref()
    }

    /// Identificador del escaneo al que pertenece el evento, si aplica.
    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }

    /// Carga útil específica del tipo de evento.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Clave de partición de Kinesis: `scan_id` (mantiene en orden todos los
    /// eventos de un escaneo), si no `actor_sub`, si no `event_id`.
    pub fn partition_key(&self) -> &str {
        self.scan_id
            .as_deref()
            .or(self.actor_sub.as_deref())
            .unwrap_or(&self.event_id)
    }
}

fn valid_id(value: &str) -> bool {
    (1..=MAX_ID_CHARS).contains(&value.chars().count())
}

fn valid_reason_code(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && value.chars().count() <= MAX_REASON_CODE_CHARS
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Texto de `ip` que acepta el schema: IPv4 en notación decimal e IPv6 en
/// ocho grupos hexadecimales (sin compresión `::` ni sufijo IPv4 embebido,
/// forma que el patrón del schema no admite).
fn schema_safe_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .map(|s| format!("{s:x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Emite `event` sin esperar ni propagar nada: lo publica en una tarea
/// `tokio` desacoplada, con tope de [`PUBLISH_TIMEOUT`]. Un fallo, un
/// timeout, un evento inválido o la ausencia de runtime solo se loggean
/// (tipo de evento y campo, nunca el contenido). Es el único punto de
/// emisión que deben usar los handlers.
pub fn emit(
    publisher: &Arc<dyn SecurityEventPublisher>,
    event: Result<SecurityEvent, InvalidSecurityEvent>,
) {
    let event = match event {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!(
                event_type = err.event_type,
                field = err.field,
                "evento de seguridad descartado: valor inválido para el contrato"
            );
            return;
        }
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            event_type = event.event_type_str(),
            "evento de seguridad descartado: no hay runtime tokio activo"
        );
        return;
    };
    let publisher = Arc::clone(publisher);
    runtime.spawn(async move { deliver(publisher, event, RetryPolicy::default()).await });
}

/// Política de reintento de una publicación: intentos acotados con backoff
/// exponencial y jitter completo, dentro del tope global [`PUBLISH_TIMEOUT`].
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Intentos totales por evento (el primero incluido).
    pub max_attempts: u32,
    /// Tope de espera antes del primer reintento; se duplica en cada uno.
    pub base_delay: Duration,
    /// Tiempo máximo de cada intento, para poder reintentar una llamada colgada.
    pub attempt_timeout: Duration,
    /// Elige la espera real dado su tope; inyectable para tests deterministas.
    pub jitter: fn(Duration) -> Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            attempt_timeout: Duration::from_millis(1500),
            jitter: full_jitter,
        }
    }
}

/// Jitter completo: un valor uniforme en `[0, cap]` (bytes aleatorios de un
/// UUID v4, sin añadir una dependencia).
pub fn full_jitter(cap: Duration) -> Duration {
    // Los 62 bits bajos de un UUID v4 son aleatorios (los altos llevan la
    // versión y la variante, constantes).
    let random = uuid::Uuid::new_v4().as_u128() & ((1u128 << 62) - 1);
    cap.mul_f64(random as f64 / (1u128 << 62) as f64)
}

/// Publica `event` con la política dada; `true` si el destino lo aceptó.
/// Cada intento tiene su propio tope; un fallo o timeout de un intento se
/// loggea (tipo e id del evento, nunca el contenido) y se reintenta tras
/// una espera con backoff exponencial y jitter. El tope global lo impone
/// quien llama (ver `deliver`).
pub async fn publish_with_retry(
    publisher: &dyn SecurityEventPublisher,
    event: &SecurityEvent,
    policy: &RetryPolicy,
) -> bool {
    for attempt in 1..=policy.max_attempts {
        let reason =
            match tokio::time::timeout(policy.attempt_timeout, publisher.publish(event)).await {
                Ok(Ok(())) => return true,
                Ok(Err(_)) => "error",
                Err(_) => "timeout",
            };
        tracing::warn!(
            attempt,
            max_attempts = policy.max_attempts,
            reason,
            event_type = event.event_type_str(),
            event_id = event.event_id(),
            "falló un intento de publicar un evento de seguridad"
        );
        if attempt < policy.max_attempts {
            let cap = policy.base_delay.saturating_mul(1 << (attempt - 1).min(16));
            tokio::time::sleep((policy.jitter)(cap)).await;
        }
    }
    false
}

async fn deliver(
    publisher: Arc<dyn SecurityEventPublisher>,
    event: SecurityEvent,
    policy: RetryPolicy,
) {
    match tokio::time::timeout(
        PUBLISH_TIMEOUT,
        publish_with_retry(publisher.as_ref(), &event, &policy),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => tracing::error!(
            event_type = event.event_type_str(),
            event_id = event.event_id(),
            "no se pudo publicar un evento de seguridad (la operación no se ve afectada)"
        ),
        Err(_) => tracing::error!(
            event_type = event.event_type_str(),
            event_id = event.event_id(),
            "se agotó el tiempo publicando un evento de seguridad (la operación no se ve afectada)"
        ),
    }
}

/// Adaptador que descarta todo evento: se usa cuando
/// `SECURITY_EVENTS_STREAM_NAME` no está definida (instalaciones locales
/// anteriores a esta feature siguen funcionando).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSecurityEventPublisher;

#[async_trait::async_trait]
impl SecurityEventPublisher for NoopSecurityEventPublisher {
    async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
        Ok(())
    }
}

/// Adaptador en memoria que conserva los eventos publicados, para tests que
/// verifican qué emite el Gateway sin Kinesis.
#[derive(Debug, Default)]
pub struct RecordingSecurityEventPublisher {
    events: Mutex<Vec<SecurityEvent>>,
}

impl RecordingSecurityEventPublisher {
    /// Crea un grabador vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copia de los eventos publicados hasta ahora, en orden.
    pub fn events(&self) -> Vec<SecurityEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Cede el turno al runtime (sin esperas de reloj) hasta que haya al
    /// menos `count` eventos, con un tope de intentos, y devuelve lo
    /// grabado. [`emit`] publica en una tarea aparte, así que los tests la
    /// usan en vez de dormir.
    pub async fn wait_for(&self, count: usize) -> Vec<SecurityEvent> {
        for _ in 0..10_000 {
            let events = self.events();
            if events.len() >= count {
                return events;
            }
            tokio::task::yield_now().await;
        }
        self.events()
    }
}

#[async_trait::async_trait]
impl SecurityEventPublisher for RecordingSecurityEventPublisher {
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_key_prefers_scan_id_then_actor_sub_then_event_id() {
        let with_scan = SecurityEvent::scan_cancelled("sub-1", "scan-1").unwrap();
        assert_eq!(with_scan.partition_key(), "scan-1");

        let with_actor = SecurityEvent::auth_login("sub-1").unwrap();
        assert_eq!(with_actor.partition_key(), "sub-1");

        let neither = SecurityEvent::message_deadlettered("q", "malformed_message").unwrap();
        assert_eq!(neither.partition_key(), neither.event_id());
    }

    #[test]
    fn envelope_has_uuid_v4_id_rfc3339_utc_timestamp_and_gateway_source() {
        let event = SecurityEvent::auth_login("sub-1").unwrap();
        let id = uuid::Uuid::parse_str(event.event_id()).expect("event_id debe ser UUID");
        assert_eq!(id.get_version_num(), 4);
        assert!(event.occurred_at().ends_with('Z'));
        time::OffsetDateTime::parse(
            event.occurred_at(),
            &time::format_description::well_known::Rfc3339,
        )
        .expect("occurred_at debe ser RFC 3339");
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["source"], "gateway");
        assert_eq!(value["event_type"], "auth.login");
    }

    #[test]
    fn absent_optional_fields_are_omitted_from_the_json() {
        let value = serde_json::to_value(
            SecurityEvent::message_deadlettered("q", "malformed_message").unwrap(),
        )
        .unwrap();
        assert!(value.get("actor_sub").is_none());
        assert!(value.get("scan_id").is_none());
        assert_eq!(value["payload"]["queue"], "q");
    }

    #[test]
    fn ratelimit_route_drops_the_query_string_and_fragment() {
        let value = serde_json::to_value(
            SecurityEvent::ratelimit_hit("sub-1", "/api/scans?token=abc#x", 10, 60).unwrap(),
        )
        .unwrap();
        assert_eq!(value["payload"]["route"], "/api/scans");
    }

    #[test]
    fn scan_requested_target_is_written_in_a_schema_safe_canonical_form() {
        let v6 = serde_json::to_value(
            SecurityEvent::scan_requested("s", "c", "::ffff:192.0.2.1").unwrap(),
        )
        .unwrap();
        assert_eq!(v6["payload"]["target"], "0:0:0:0:0:ffff:c000:201");
        let v4 =
            serde_json::to_value(SecurityEvent::scan_requested("s", "c", "192.0.2.10").unwrap())
                .unwrap();
        assert_eq!(v4["payload"]["target"], "192.0.2.10");
    }

    #[test]
    fn constructors_refuse_values_the_schema_would_reject() {
        assert!(SecurityEvent::auth_login("").is_err());
        assert!(SecurityEvent::auth_login(&"x".repeat(129)).is_err());
        assert!(SecurityEvent::auth_login(&"x".repeat(128)).is_ok());
        assert!(SecurityEvent::scan_cancelled("s", "").is_err());
        assert!(SecurityEvent::scan_requested("s", "c", "10.0.0.0/24").is_err());
        assert!(SecurityEvent::scan_requested("s", "c", "example.com").is_err());
        assert!(SecurityEvent::ratelimit_hit("s", "api/scans", 1, 1).is_err());
        assert!(SecurityEvent::ratelimit_hit("s", "/a b", 1, 1).is_err());
        assert!(SecurityEvent::ratelimit_hit("s", &format!("/{}", "a".repeat(200)), 1, 1).is_err());
        assert!(SecurityEvent::ratelimit_hit("s", "/x", 0, 1).is_err());
        assert!(SecurityEvent::ratelimit_hit("s", "/x", 1, 0).is_err());
        assert!(SecurityEvent::message_deadlettered("bad queue!", "malformed_message").is_err());
        assert!(SecurityEvent::message_deadlettered("q", "Malformed Message").is_err());
    }

    #[test]
    fn invalid_event_error_names_the_field_but_never_the_value() {
        let err = SecurityEvent::auth_login("secret-looking-value".repeat(20).as_str())
            .expect_err("sub demasiado largo");
        let text = err.to_string();
        assert!(text.contains("actor_sub"));
        assert!(!text.contains("secret-looking-value"));
    }

    #[tokio::test]
    async fn recording_publisher_keeps_published_events_in_order() {
        let recorder = RecordingSecurityEventPublisher::new();
        recorder
            .publish(&SecurityEvent::auth_login("a").unwrap())
            .await
            .unwrap();
        recorder
            .publish(&SecurityEvent::auth_logout("a").unwrap())
            .await
            .unwrap();
        let types: Vec<_> = recorder
            .events()
            .iter()
            .map(|e| e.event_type_str().to_string())
            .collect();
        assert_eq!(types, ["auth.login", "auth.logout"]);
    }

    #[tokio::test]
    async fn noop_publisher_accepts_everything() {
        NoopSecurityEventPublisher
            .publish(&SecurityEvent::auth_login("a").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn emit_delivers_in_the_background() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit(&port, SecurityEvent::auth_login("a"));
        let events = recorder.wait_for(1).await;
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn emit_with_a_failing_publisher_neither_panics_nor_blocks() {
        let port: Arc<dyn SecurityEventPublisher> = Arc::new(FailingPublisher);
        emit(&port, SecurityEvent::auth_login("a"));
        // `emit` es síncrona: si hubiera esperado o propagado el fallo, no
        // habría devuelto el control aquí.
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn emit_with_an_invalid_event_drops_it_without_publishing() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit(&port, SecurityEvent::auth_login(""));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(recorder.events().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn emit_gives_up_on_a_hanging_publisher_after_the_timeout() {
        let hanging = Arc::new(HangingPublisher);
        let port: Arc<dyn SecurityEventPublisher> = hanging.clone();
        emit(&port, SecurityEvent::auth_login("a"));
        drop(port);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&hanging), 2, "la tarea sigue publicando");

        tokio::time::advance(PUBLISH_TIMEOUT + std::time::Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            Arc::strong_count(&hanging),
            1,
            "la tarea debe haberse soltado"
        );
    }

    #[derive(Clone, Copy)]
    enum Step {
        Fail,
        Hang,
        Ok,
    }

    /// Publicador con guion: cada intento consume un paso; sin pasos, falla.
    struct Scripted {
        steps: Mutex<std::collections::VecDeque<Step>>,
        attempts: Mutex<u32>,
        published: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(steps: &[Step]) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps.iter().copied().collect()),
                attempts: Mutex::new(0),
                published: Mutex::new(Vec::new()),
            })
        }
        fn attempts(&self) -> u32 {
            *self.attempts.lock().unwrap()
        }
        fn published(&self) -> Vec<String> {
            self.published.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SecurityEventPublisher for Scripted {
        async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError> {
            *self.attempts.lock().unwrap() += 1;
            let step = self.steps.lock().unwrap().pop_front().unwrap_or(Step::Fail);
            match step {
                Step::Ok => {
                    self.published
                        .lock()
                        .unwrap()
                        .push(event.event_id().to_string());
                    Ok(())
                }
                Step::Fail => Err(SecurityEventError::PublishFailed("boom".into())),
                Step::Hang => std::future::pending().await,
            }
        }
    }

    fn max_jitter_policy() -> RetryPolicy {
        RetryPolicy {
            jitter: |cap| cap,
            ..RetryPolicy::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transient_failure_then_success_publishes_once_after_retry() {
        let publisher = Scripted::new(&[Step::Fail, Step::Ok]);
        let event = SecurityEvent::auth_login("a").unwrap();
        assert!(publish_with_retry(publisher.as_ref(), &event, &max_jitter_policy()).await);
        assert_eq!(publisher.attempts(), 2);
        assert_eq!(publisher.published(), [event.event_id()]);
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_failure_makes_exactly_max_attempts_within_the_budget() {
        let publisher = Scripted::new(&[]);
        let event = SecurityEvent::auth_login("a").unwrap();
        let start = tokio::time::Instant::now();
        assert!(!publish_with_retry(publisher.as_ref(), &event, &max_jitter_policy()).await);
        assert_eq!(publisher.attempts(), 3);
        assert!(start.elapsed() <= PUBLISH_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_attempt_is_cut_by_the_attempt_timeout_and_retried() {
        let publisher = Scripted::new(&[Step::Hang, Step::Ok]);
        let event = SecurityEvent::auth_login("a").unwrap();
        let start = tokio::time::Instant::now();
        assert!(publish_with_retry(publisher.as_ref(), &event, &max_jitter_policy()).await);
        assert_eq!(publisher.attempts(), 2);
        assert!(start.elapsed() >= RetryPolicy::default().attempt_timeout);
        assert!(start.elapsed() < PUBLISH_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn all_attempts_hanging_still_finish_within_the_overall_budget() {
        let publisher = Scripted::new(&[Step::Hang, Step::Hang, Step::Hang]);
        let port: Arc<dyn SecurityEventPublisher> = publisher.clone();
        let start = tokio::time::Instant::now();
        deliver(
            port,
            SecurityEvent::auth_login("a").unwrap(),
            max_jitter_policy(),
        )
        .await;
        assert_eq!(publisher.attempts(), 3);
        assert!(start.elapsed() <= PUBLISH_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn emit_retries_in_the_background_after_a_transient_failure() {
        let publisher = Scripted::new(&[Step::Fail, Step::Ok]);
        let port: Arc<dyn SecurityEventPublisher> = publisher.clone();
        emit(&port, SecurityEvent::auth_login("a"));
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher.attempts(), 2);
        assert_eq!(publisher.published().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_event_is_not_retried_nor_published() {
        let publisher = Scripted::new(&[Step::Ok]);
        let port: Arc<dyn SecurityEventPublisher> = publisher.clone();
        emit(&port, SecurityEvent::auth_login(""));
        tokio::time::advance(Duration::from_secs(6)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher.attempts(), 0);
    }

    #[test]
    fn full_jitter_stays_within_zero_and_cap() {
        let cap = Duration::from_millis(200);
        let samples: Vec<_> = (0..200).map(|_| full_jitter(cap)).collect();
        assert!(samples.iter().all(|d| *d <= cap));
        assert!(
            samples.iter().any(|d| *d < cap / 4),
            "debe cubrir el tramo bajo"
        );
        assert!(
            samples.iter().any(|d| *d > cap * 3 / 4),
            "debe cubrir el tramo alto"
        );
    }

    struct FailingPublisher;

    #[async_trait::async_trait]
    impl SecurityEventPublisher for FailingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            Err(SecurityEventError::PublishFailed("boom".into()))
        }
    }

    struct HangingPublisher;

    #[async_trait::async_trait]
    impl SecurityEventPublisher for HangingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            std::future::pending().await
        }
    }
}
