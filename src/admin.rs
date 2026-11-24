//! Tipos del panel de administración y estado compartido de sus rutas
//! (feature `admin_realtime_feed`, tarea KAP-09; desde la feature
//! `admin_feed_proxy` el gateway ya no agrega nada).
//!
//! La lectura de Kinesis y el agregador viven en `events-service`; el gateway
//! solo reenvía `GET /metrics` y `GET /events` ([`crate::events_client`],
//! [`crate::admin_routes`]). Los tipos de este módulo describen el JSON que
//! ese servicio emite (copiado byte a byte del antiguo agregador) y existen
//! únicamente para que la especificación OpenAPI de `/api/admin/*` siga
//! documentando los mismos esquemas: el gateway nunca los construye ni los
//! deserializa.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::events_client::EventsClient;

/// Agente Wazuh que originó una alerta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SiemAgent {
    /// `agent.id` de Wazuh.
    pub id: String,
    /// `agent.name` de Wazuh.
    pub name: String,
}

/// Alerta SIEM (`siem.alert`). Solo viaja en `siem_alerts` (snapshot) y
/// `siem_alert` (delta); no forma parte de `recent_events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SiemAlert {
    /// `event_id` del evento (identificador estable para el cliente).
    pub event_id: String,
    /// Instante del evento según el productor.
    pub occurred_at: String,
    /// `low`, `medium`, `high` o `critical`.
    #[schema(example = "high")]
    pub severity: SiemSeverity,
    /// `rule.id` de Wazuh.
    pub rule_id: String,
    /// `rule.level` de Wazuh (0..16).
    #[schema(maximum = 16)]
    pub rule_level: u8,
    /// Descripción de la regla (máx. 256).
    #[schema(max_length = 256)]
    pub description: String,
    /// Agente que la reportó.
    pub agent: SiemAgent,
    /// IP de origen, si la hay.
    pub src_ip: Option<String>,
    /// IP de destino, si la hay.
    pub dest_ip: Option<String>,
    /// Firma de Suricata, si la alerta viene de Suricata.
    pub signature: Option<String>,
}

/// Severidad de una alerta SIEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SiemSeverity {
    /// Niveles 0-6.
    Low,
    /// Niveles 7-9.
    Medium,
    /// Niveles 10-12.
    High,
    /// Niveles 13-16.
    Critical,
}

/// Alertas SIEM por severidad (las cuatro claves siempre presentes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct SiemSeverityCounts {
    /// Severidad `low`.
    pub low: u64,
    /// Severidad `medium`.
    pub medium: u64,
    /// Severidad `high`.
    pub high: u64,
    /// Severidad `critical`.
    pub critical: u64,
}

/// Estado de un escaneo en curso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanFlightStatus {
    /// Pedido y aceptado por el Broker, sin `scan.started` todavía.
    Requested,
    /// `nmap-service` ya lo empezó.
    Running,
}

/// Cambio de un escaneo en un [`AdminDelta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanChangeStatus {
    /// Entró en curso como `requested`.
    Requested,
    /// Pasó a `running`.
    Running,
    /// Terminó (completado, fallido o cancelado): sale de la lista.
    Finished,
}

/// Escaneo en curso.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct InFlightScan {
    /// Identificador del escaneo.
    pub scan_id: String,
    /// Estado actual.
    pub status: ScanFlightStatus,
    /// Instante (RFC 3339, UTC) en que se empezó a rastrear.
    pub since: String,
}

/// Hallazgo crítico (`finding.critical`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CriticalFinding {
    /// `event_id` del evento (identificador estable para el cliente).
    pub event_id: String,
    /// Instante del evento según el productor.
    pub occurred_at: String,
    /// Escaneo al que pertenece.
    pub scan_id: String,
    /// Puerto afectado; `None` (`null`) en un hallazgo a nivel de host.
    pub port: Option<u16>,
    /// `tcp` o `udp`; `None` (`null`) en un hallazgo a nivel de host.
    pub protocol: Option<String>,
    /// CVE asociado, si lo hay.
    pub cve_id: Option<String>,
    /// `high` o `critical`.
    pub severity: String,
    /// `confirmed` o `version_match`.
    pub confidence: String,
}

/// Entrada del registro de eventos: campos del sobre más el `payload`, nada más.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct EventEntry {
    /// UUID del evento.
    pub event_id: String,
    /// Tipo del evento (`scan.requested`, ...).
    pub event_type: String,
    /// Instante del evento según el productor (RFC 3339).
    pub occurred_at: String,
    /// Servicio productor.
    pub source: String,
    /// `sub` seudónimo del usuario que causó el evento, si aplica.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_sub: Option<String>,
    /// Escaneo al que pertenece el evento, si aplica.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    /// Carga útil del contrato para ese tipo de evento.
    pub payload: Value,
}

/// Indicadores clave del panel.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Kpis {
    /// Escaneos en curso (pedidos o empezados, sin evento terminal).
    pub scans_in_flight: u64,
    /// `scan.completed` en la ventana.
    pub completed_last_window: u64,
    /// `scan.failed` en la ventana.
    pub failed_last_window: u64,
    /// `failed / (completed + failed)` en la ventana; `null` sin escaneos.
    pub failure_rate: Option<f64>,
    /// Usuarios distintos con login en la ventana y sin logout posterior.
    pub active_users: u64,
    /// `ratelimit.hit` en la ventana.
    pub rate_limit_hits: u64,
    /// Registros descartados por malformados desde que arrancó el proceso.
    pub malformed_records: u64,
    /// `siem.alert` en la ventana (0 con el SIEM apagado).
    pub siem_alerts: u64,
    /// `siem.alert` en la ventana por severidad.
    pub siem_alerts_by_severity: SiemSeverityCounts,
}

/// Vista completa del estado, que sirve `GET /api/admin/metrics` y el primer
/// evento `snapshot` del stream SSE.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AdminSnapshot {
    /// Número de secuencia del último delta que refleja este snapshot.
    pub seq: u64,
    /// Instante (RFC 3339, UTC) en que se generó.
    pub generated_at: String,
    /// Ancho de la ventana de los KPIs, en segundos.
    pub window_seconds: u64,
    /// Indicadores clave.
    pub kpis: Kpis,
    /// Escaneos en curso, del más antiguo al más reciente.
    pub scans_in_flight: Vec<InFlightScan>,
    /// Hallazgos críticos, el más reciente primero (máx. 50).
    pub critical_findings: Vec<CriticalFinding>,
    /// Últimos eventos, el más reciente primero (máx. 100).
    pub recent_events: Vec<EventEntry>,
    /// Serie por minuto de los últimos 15 minutos.
    pub series: AdminSeries,
    /// Si el SIEM está habilitado (`SIEM_ENABLED`); el front muestra la
    /// pestaña de alertas solo entonces.
    pub siem_enabled: bool,
    /// Alertas SIEM, la más reciente primero (máx. 8, `MAX_SIEM_ALERTS` en
    /// `events-service`); vacío con el SIEM apagado. No se repiten en
    /// `recent_events`.
    pub siem_alerts: Vec<SiemAlert>,
}

/// Serie temporal: exactamente 15 cubetas de un minuto (UTC), la más antigua
/// primero; la última es el minuto actual. Las cubetas vacías llevan mapas
/// vacíos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AdminSeries {
    /// Ancho de cada cubeta, en segundos (siempre 60).
    pub bucket_seconds: u64,
    /// Cubetas, la más antigua primero.
    pub buckets: Vec<SeriesBucket>,
}

/// Conteos de un minuto de la serie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SeriesBucket {
    /// Inicio del minuto (RFC 3339, UTC).
    pub minute: String,
    /// Eventos por `event_type`.
    pub by_type: std::collections::BTreeMap<String, u64>,
    /// `finding.critical` por severidad (`high` o `critical`).
    pub findings_by_severity: std::collections::BTreeMap<String, u64>,
    /// `siem.alert` por severidad (`low`, `medium`, `high`, `critical`);
    /// solo las severidades con alertas.
    pub siem_alerts_by_severity: std::collections::BTreeMap<String, u64>,
}

/// Cambio de un escaneo en curso.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ScanChange {
    /// Escaneo afectado.
    pub scan_id: String,
    /// Nuevo estado.
    pub status: ScanChangeStatus,
}

/// Cambio incremental que emite el agregador tras cada evento (o registro
/// malformado).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AdminDelta {
    /// Número de secuencia, creciente de a uno.
    pub seq: u64,
    /// Evento que se añade al registro; ausente si el delta es solo por un
    /// registro malformado.
    ///
    /// Es `null` en el delta de una alerta SIEM: esa alerta viaja en
    /// `siem_alert`, no en el registro de eventos.
    pub event: Option<EventEntry>,
    /// KPIs completos tras aplicar el cambio.
    pub kpis: Kpis,
    /// Cambio en la lista de escaneos en curso, si lo hubo.
    pub scan_change: Option<ScanChange>,
    /// Hallazgo crítico nuevo, si el evento era `finding.critical`.
    pub critical_finding: Option<CriticalFinding>,
    /// Alerta SIEM nueva, si el evento era `siem.alert`.
    pub siem_alert: Option<SiemAlert>,
}

/// Estado compartido de las rutas de administración: el cliente hacia
/// `events-service` y cada cuánto se revalida el rol en un stream SSE abierto.
#[derive(Debug, Clone)]
pub struct AdminFeed {
    /// Cliente hacia `events-service`.
    pub client: Arc<EventsClient>,
    /// Cada cuánto un stream SSE reconsulta el rol vigente del usuario.
    pub role_recheck_interval: Duration,
}

/// Intervalo por defecto de revalidación del rol en un stream SSE.
pub const DEFAULT_ROLE_RECHECK_INTERVAL: Duration = Duration::from_secs(60);

impl AdminFeed {
    /// Feed con `client` y el intervalo de revalidación indicado.
    pub fn new(client: Arc<EventsClient>, role_recheck_interval: Duration) -> Self {
        Self {
            client,
            role_recheck_interval,
        }
    }
}

impl Default for AdminFeed {
    /// Feed hacia un `events-service` inexistente (`.invalid`) con el
    /// intervalo por defecto: para los tests de rutas que no tocan el panel.
    fn default() -> Self {
        let client = EventsClient::new(
            "http://events-service.invalid".to_string(),
            secrecy::SecretString::from(String::new()),
        )
        .expect("el cliente HTTP por defecto debe construirse");
        Self::new(Arc::new(client), DEFAULT_ROLE_RECHECK_INTERVAL)
    }
}
