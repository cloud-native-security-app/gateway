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
    pub event: Option<EventEntry>,
    /// KPIs completos tras aplicar el cambio.
    pub kpis: Kpis,
    /// Cambio en la lista de escaneos en curso, si lo hubo.
    pub scan_change: Option<ScanChange>,
    /// Hallazgo crítico nuevo, si el evento era `finding.critical`.
    pub critical_finding: Option<CriticalFinding>,
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
