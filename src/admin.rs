//! Agregador en memoria de las métricas del panel de administración
//! (feature `admin_realtime_feed`, tarea KAP-09).
//!
//! Recibe cada [`SecurityEvent`] ya validado que lee el consumidor de Kinesis
//! ([`crate::kinesis_consumer`]) y mantiene el estado que sirven
//! `GET /api/admin/metrics` y `GET /api/admin/events`
//! ([`crate::admin_routes`]): escaneos en curso, completados y fallidos de la
//! última ventana, usuarios activos, límites de tasa, hallazgos críticos y el
//! registro de eventos recientes.
//!
//! ## Decisiones de diseño
//!
//! - **Puro y con reloj inyectado**: el agregador no llama a `SystemTime`;
//!   recibe un [`Clock`]. Los tests usan [`ManualClock`] y no duermen.
//! - **La ventana usa la hora de recepción, no `occurred_at`**: un productor
//!   con el reloj desfasado (o malicioso) no puede meter ni sacar eventos de
//!   la ventana. `occurred_at` se muestra tal cual en el registro.
//! - **Memoria acotada**: contadores por cubetas de un segundo (a lo sumo
//!   [`WINDOW_SECS`] entradas), escaneos en curso con tope y vencimiento,
//!   usuarios activos con tope, hallazgos y registro con tope, y un conjunto
//!   acotado de `event_id` recientes para ignorar reentregas (Kinesis entrega
//!   al menos una vez).
//! - **Deltas con valores absolutos**: cada [`AdminDelta`] lleva los KPIs
//!   completos tras aplicar el evento, así que un delta perdido se corrige
//!   solo con el siguiente. El `seq` creciente permite a un cliente detectar
//!   huecos; el snapshot lleva el `seq` que refleja.
//! - **Sin PII**: el registro conserva solo los campos del sobre y el
//!   `payload` (lo que el schema permite). `actor_sub` es un identificador
//!   seudónimo; nunca hay correos, nombres ni tokens en un evento.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use utoipa::ToSchema;

use crate::security_events::{EventType, SecurityEvent};

/// Ancho de la ventana deslizante de los KPIs, en segundos (15 minutos).
pub const WINDOW_SECS: u64 = 900;
/// Máximo de hallazgos críticos retenidos.
pub const MAX_CRITICAL_FINDINGS: usize = 50;
/// Máximo de eventos en el registro reciente.
pub const MAX_RECENT_EVENTS: usize = 100;
/// Máximo de escaneos en curso rastreados.
pub const MAX_IN_FLIGHT: usize = 1000;
/// Edad máxima de un escaneo en curso: pasado ese tiempo se asume que su
/// evento terminal se perdió y se descarta.
pub const IN_FLIGHT_MAX_AGE_SECS: i64 = 3600;
/// Máximo de usuarios activos rastreados.
pub const MAX_ACTIVE_USERS: usize = 10_000;
/// Máximo de `event_id` recordados para ignorar reentregas.
pub const DEDUPE_CAPACITY: usize = 2048;
/// Capacidad del canal de deltas: un cliente SSE más lento que esto recibe un
/// snapshot nuevo en vez de un error (ver [`crate::admin_routes`]).
pub const DELTA_CHANNEL_CAPACITY: usize = 256;

/// Fuente de tiempo del agregador (milisegundos desde la época Unix).
pub trait Clock: Send + Sync {
    /// Instante actual en milisegundos desde la época Unix.
    fn now_ms(&self) -> i64;
}

/// Reloj real del sistema.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
    }
}

/// Reloj manual para tests: solo avanza cuando se le ordena.
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// Reloj detenido en `start_ms` (milisegundos desde la época Unix).
    pub fn new(start_ms: i64) -> Self {
        Self(AtomicI64::new(start_ms))
    }

    /// Avanza el reloj `by`.
    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_millis() as i64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
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
    /// Puerto afectado.
    pub port: u16,
    /// `tcp` o `udp`.
    pub protocol: String,
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

/// Contador por cubetas de un segundo sobre la ventana deslizante: memoria
/// acotada por [`WINDOW_SECS`] sin importar el caudal.
#[derive(Debug, Default)]
struct WindowCounter {
    buckets: VecDeque<(i64, u64)>,
}

impl WindowCounter {
    fn add(&mut self, now_ms: i64) {
        let sec = now_ms.div_euclid(1000);
        match self.buckets.back_mut() {
            Some((last, count)) if *last == sec => *count += 1,
            _ => self.buckets.push_back((sec, 1)),
        }
    }

    fn count(&mut self, now_ms: i64) -> u64 {
        let oldest_alive = now_ms.div_euclid(1000) - WINDOW_SECS as i64;
        while self
            .buckets
            .front()
            .is_some_and(|(sec, _)| *sec <= oldest_alive)
        {
            self.buckets.pop_front();
        }
        self.buckets.iter().map(|(_, count)| count).sum()
    }
}

#[derive(Debug)]
struct InFlightEntry {
    status: ScanFlightStatus,
    since_ms: i64,
}

#[derive(Debug, Default)]
struct State {
    seq: u64,
    completed: WindowCounter,
    failed: WindowCounter,
    rate_limit_hits: WindowCounter,
    in_flight: HashMap<String, InFlightEntry>,
    /// `actor_sub` -> instante (ms) del último login sin logout posterior.
    active_users: HashMap<String, i64>,
    critical_findings: VecDeque<CriticalFinding>,
    recent_events: VecDeque<EventEntry>,
    malformed_records: u64,
    seen_ids: HashSet<String>,
    seen_order: VecDeque<String>,
}

fn window_ms() -> i64 {
    WINDOW_SECS as i64 * 1000
}

impl State {
    /// Descarta lo vencido (escaneos sin evento terminal, usuarios fuera de la
    /// ventana).
    fn prune(&mut self, now_ms: i64) {
        self.in_flight
            .retain(|_, entry| now_ms - entry.since_ms < IN_FLIGHT_MAX_AGE_SECS * 1000);
        self.active_users.retain(|_, at| now_ms - *at < window_ms());
    }

    fn kpis(&mut self, now_ms: i64) -> Kpis {
        self.prune(now_ms);
        let completed = self.completed.count(now_ms);
        let failed = self.failed.count(now_ms);
        let finished = completed + failed;
        Kpis {
            scans_in_flight: self.in_flight.len() as u64,
            completed_last_window: completed,
            failed_last_window: failed,
            failure_rate: (finished > 0).then(|| failed as f64 / finished as f64),
            active_users: self.active_users.len() as u64,
            rate_limit_hits: self.rate_limit_hits.count(now_ms),
            malformed_records: self.malformed_records,
        }
    }

    /// `true` si `event_id` ya se vio (y, si no, lo recuerda con tope).
    fn already_seen(&mut self, event_id: &str) -> bool {
        if self.seen_ids.contains(event_id) {
            return true;
        }
        if self.seen_order.len() >= DEDUPE_CAPACITY {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_ids.remove(&oldest);
            }
        }
        self.seen_ids.insert(event_id.to_string());
        self.seen_order.push_back(event_id.to_string());
        false
    }

    fn track_scan(&mut self, scan_id: &str, status: ScanFlightStatus, now_ms: i64) -> ScanChange {
        if let Some(existing) = self.in_flight.get_mut(scan_id) {
            // Un `scan.requested` tardío o repetido no degrada a `running`.
            if status == ScanFlightStatus::Running {
                existing.status = ScanFlightStatus::Running;
            }
            let status = existing.status;
            return ScanChange {
                scan_id: scan_id.to_string(),
                status: status.into(),
            };
        }
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            if let Some(oldest) = self
                .in_flight
                .iter()
                .min_by_key(|(_, entry)| entry.since_ms)
                .map(|(id, _)| id.clone())
            {
                self.in_flight.remove(&oldest);
            }
        }
        self.in_flight.insert(
            scan_id.to_string(),
            InFlightEntry {
                status,
                since_ms: now_ms,
            },
        );
        ScanChange {
            scan_id: scan_id.to_string(),
            status: status.into(),
        }
    }

    fn login(&mut self, actor: &str, now_ms: i64) {
        if self.active_users.len() >= MAX_ACTIVE_USERS && !self.active_users.contains_key(actor) {
            self.prune(now_ms);
            if self.active_users.len() >= MAX_ACTIVE_USERS {
                if let Some(oldest) = self
                    .active_users
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(sub, _)| sub.clone())
                {
                    self.active_users.remove(&oldest);
                }
            }
        }
        self.active_users.insert(actor.to_string(), now_ms);
    }
}

impl From<ScanFlightStatus> for ScanChangeStatus {
    fn from(status: ScanFlightStatus) -> Self {
        match status {
            ScanFlightStatus::Requested => Self::Requested,
            ScanFlightStatus::Running => Self::Running,
        }
    }
}

fn rfc3339_from_ms(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|at| at.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn event_entry(event: &SecurityEvent) -> EventEntry {
    EventEntry {
        event_id: event.event_id().to_string(),
        event_type: event.event_type_str().to_string(),
        occurred_at: event.occurred_at().to_string(),
        source: match event.source() {
            crate::security_events::EventSource::Gateway => "gateway",
            crate::security_events::EventSource::NmapService => "nmap-service",
            crate::security_events::EventSource::UserService => "user-service",
        }
        .to_string(),
        actor_sub: event.actor_sub().map(str::to_string),
        scan_id: event.scan_id().map(str::to_string),
        payload: event.payload().clone(),
    }
}

fn critical_finding(event: &SecurityEvent) -> Option<CriticalFinding> {
    let payload = event.payload();
    let text = |key: &str| payload.get(key)?.as_str().map(str::to_string);
    Some(CriticalFinding {
        event_id: event.event_id().to_string(),
        occurred_at: event.occurred_at().to_string(),
        scan_id: event.scan_id()?.to_string(),
        port: u16::try_from(payload.get("port")?.as_u64()?).ok()?,
        protocol: text("protocol")?,
        cve_id: text("cve_id"),
        severity: text("severity")?,
        confidence: text("confidence")?,
    })
}

/// Agregador de métricas de administración (ver la documentación del módulo).
pub struct AdminAggregator {
    clock: Arc<dyn Clock>,
    inner: Mutex<State>,
    deltas: broadcast::Sender<AdminDelta>,
}

impl std::fmt::Debug for AdminAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAggregator").finish_non_exhaustive()
    }
}

impl AdminAggregator {
    /// Agregador vacío con el reloj indicado.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            inner: Mutex::new(State::default()),
            deltas: broadcast::channel(DELTA_CHANNEL_CAPACITY).0,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Aplica `event` al estado y emite su [`AdminDelta`]. Un `event_id` ya
    /// visto (reentrega de Kinesis) se ignora.
    pub fn ingest(&self, event: &SecurityEvent) {
        let now_ms = self.clock.now_ms();
        let mut state = self.lock();
        if state.already_seen(event.event_id()) {
            return;
        }

        let mut scan_change = None;
        let mut critical = None;
        let scan_id = event.scan_id();
        match (event.event_type(), scan_id) {
            (EventType::ScanRequested, Some(id)) => {
                scan_change = Some(state.track_scan(id, ScanFlightStatus::Requested, now_ms));
            }
            (EventType::ScanStarted, Some(id)) => {
                scan_change = Some(state.track_scan(id, ScanFlightStatus::Running, now_ms));
            }
            (
                EventType::ScanCompleted | EventType::ScanFailed | EventType::ScanCancelled,
                Some(id),
            ) => {
                state.in_flight.remove(id);
                scan_change = Some(ScanChange {
                    scan_id: id.to_string(),
                    status: ScanChangeStatus::Finished,
                });
                match event.event_type() {
                    EventType::ScanCompleted => state.completed.add(now_ms),
                    EventType::ScanFailed => state.failed.add(now_ms),
                    _ => {}
                }
            }
            (EventType::FindingCritical, _) => {
                if let Some(finding) = critical_finding(event) {
                    state.critical_findings.push_front(finding.clone());
                    state.critical_findings.truncate(MAX_CRITICAL_FINDINGS);
                    critical = Some(finding);
                }
            }
            (EventType::AuthLogin, _) => {
                if let Some(actor) = event.actor_sub() {
                    state.login(actor, now_ms);
                }
            }
            (EventType::AuthLogout, _) => {
                if let Some(actor) = event.actor_sub() {
                    state.active_users.remove(actor);
                }
            }
            (EventType::RatelimitHit, _) => state.rate_limit_hits.add(now_ms),
            _ => {}
        }

        let entry = event_entry(event);
        state.recent_events.push_front(entry.clone());
        state.recent_events.truncate(MAX_RECENT_EVENTS);

        state.seq += 1;
        let delta = AdminDelta {
            seq: state.seq,
            event: Some(entry),
            kpis: state.kpis(now_ms),
            scan_change,
            critical_finding: critical,
        };
        // Sin receptores `send` devuelve `Err`: nadie escucha ahora mismo.
        let _ = self.deltas.send(delta);
    }

    /// Cuenta un registro descartado por malformado (JSON inválido o fuera
    /// del contrato) y lo anuncia a los clientes SSE.
    pub fn record_malformed(&self) {
        let now_ms = self.clock.now_ms();
        let mut state = self.lock();
        state.malformed_records += 1;
        state.seq += 1;
        let delta = AdminDelta {
            seq: state.seq,
            event: None,
            kpis: state.kpis(now_ms),
            scan_change: None,
            critical_finding: None,
        };
        let _ = self.deltas.send(delta);
    }

    fn snapshot_locked(&self, state: &mut State) -> AdminSnapshot {
        let now_ms = self.clock.now_ms();
        let kpis = state.kpis(now_ms);
        let mut in_flight: Vec<_> = state
            .in_flight
            .iter()
            .map(|(scan_id, entry)| (entry.since_ms, scan_id, entry.status))
            .collect();
        in_flight.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        AdminSnapshot {
            seq: state.seq,
            generated_at: rfc3339_from_ms(now_ms),
            window_seconds: WINDOW_SECS,
            kpis,
            scans_in_flight: in_flight
                .into_iter()
                .map(|(since_ms, scan_id, status)| InFlightScan {
                    scan_id: scan_id.clone(),
                    status,
                    since: rfc3339_from_ms(since_ms),
                })
                .collect(),
            critical_findings: state.critical_findings.iter().cloned().collect(),
            recent_events: state.recent_events.iter().cloned().collect(),
        }
    }

    /// Estado actual completo.
    pub fn snapshot(&self) -> AdminSnapshot {
        let mut state = self.lock();
        self.snapshot_locked(&mut state)
    }

    /// Snapshot y receptor de deltas tomados bajo el mismo candado: el primer
    /// delta que reciba el cliente es el inmediatamente posterior al snapshot
    /// (ningún evento se pierde ni se duplica).
    pub fn subscribe_with_snapshot(&self) -> (AdminSnapshot, broadcast::Receiver<AdminDelta>) {
        let mut state = self.lock();
        let receiver = self.deltas.subscribe();
        (self.snapshot_locked(&mut state), receiver)
    }
}

/// Estado compartido de las rutas de administración: el agregador y cada
/// cuánto se revalida el rol en un stream SSE abierto.
#[derive(Debug, Clone)]
pub struct AdminFeed {
    /// Agregador alimentado por el consumidor de Kinesis.
    pub aggregator: Arc<AdminAggregator>,
    /// Cada cuánto un stream SSE reconsulta el rol vigente del usuario.
    pub role_recheck_interval: Duration,
}

/// Intervalo por defecto de revalidación del rol en un stream SSE.
pub const DEFAULT_ROLE_RECHECK_INTERVAL: Duration = Duration::from_secs(60);

impl AdminFeed {
    /// Feed con `aggregator` y el intervalo de revalidación indicado.
    pub fn new(aggregator: Arc<AdminAggregator>, role_recheck_interval: Duration) -> Self {
        Self {
            aggregator,
            role_recheck_interval,
        }
    }
}

impl Default for AdminFeed {
    /// Feed vacío con reloj real y el intervalo por defecto (tests y
    /// despliegues sin stream configurado).
    fn default() -> Self {
        Self::new(
            Arc::new(AdminAggregator::new(Arc::new(SystemClock))),
            DEFAULT_ROLE_RECHECK_INTERVAL,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::{json, Value};
    use tokio::sync::broadcast::error::TryRecvError;

    use super::*;
    use crate::security_events::SecurityEvent;

    fn aggregator() -> (AdminAggregator, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(1_800_000_000_000));
        (AdminAggregator::new(clock.clone()), clock)
    }

    /// Construye un evento a partir de campos del contrato; `n` da un
    /// `event_id` único y determinista.
    fn event(
        n: u64,
        event_type: &str,
        actor: Option<&str>,
        scan: Option<&str>,
        payload: Value,
    ) -> SecurityEvent {
        let mut value = json!({
            "event_id": format!("00000000-0000-4000-8000-{n:012}"),
            "event_type": event_type,
            "occurred_at": "2026-11-10T12:00:00Z",
            "source": "gateway",
            "payload": payload,
        });
        if let Some(actor) = actor {
            value["actor_sub"] = json!(actor);
        }
        if let Some(scan) = scan {
            value["scan_id"] = json!(scan);
        }
        serde_json::from_value(value).expect("evento de prueba válido")
    }

    fn completed(n: u64, scan: &str) -> SecurityEvent {
        event(
            n,
            "scan.completed",
            None,
            Some(scan),
            json!({"duration_ms": 10, "finding_counts": {"critical":0,"high":0,"medium":0,"low":0,"info":0,"unknown":0}}),
        )
    }

    fn failed(n: u64, scan: &str) -> SecurityEvent {
        event(
            n,
            "scan.failed",
            None,
            Some(scan),
            json!({"reason_code": "ssh_timeout"}),
        )
    }

    fn requested(n: u64, scan: &str) -> SecurityEvent {
        event(
            n,
            "scan.requested",
            Some("u1"),
            Some(scan),
            json!({"target": "198.51.100.4"}),
        )
    }

    fn started(n: u64, scan: &str) -> SecurityEvent {
        event(n, "scan.started", None, Some(scan), json!({}))
    }

    fn login(n: u64, actor: &str) -> SecurityEvent {
        event(n, "auth.login", Some(actor), None, json!({}))
    }

    fn logout(n: u64, actor: &str) -> SecurityEvent {
        event(n, "auth.logout", Some(actor), None, json!({}))
    }

    fn critical(n: u64, scan: &str) -> SecurityEvent {
        event(
            n,
            "finding.critical",
            None,
            Some(scan),
            json!({"port": 22, "protocol": "tcp", "cve_id": "CVE-2023-38408", "severity": "critical", "confidence": "confirmed"}),
        )
    }

    fn ratelimit(n: u64) -> SecurityEvent {
        event(
            n,
            "ratelimit.hit",
            Some("u1"),
            None,
            json!({"route": "/api/scans", "limit": 10, "window_seconds": 60}),
        )
    }

    #[test]
    fn completed_and_failed_count_inside_the_window_and_expire_after_it() {
        let (agg, clock) = aggregator();
        agg.ingest(&completed(1, "s1"));
        agg.ingest(&failed(2, "s2"));
        clock.advance(Duration::from_secs(899));
        let kpis = agg.snapshot().kpis;
        assert_eq!(
            (kpis.completed_last_window, kpis.failed_last_window),
            (1, 1)
        );

        clock.advance(Duration::from_secs(1));
        let kpis = agg.snapshot().kpis;
        assert_eq!(
            (kpis.completed_last_window, kpis.failed_last_window),
            (0, 0)
        );
    }

    #[test]
    fn failure_rate_is_failed_over_finished_and_null_without_scans() {
        let (agg, _clock) = aggregator();
        assert_eq!(agg.snapshot().kpis.failure_rate, None);
        agg.ingest(&completed(1, "a"));
        agg.ingest(&completed(2, "b"));
        agg.ingest(&completed(3, "c"));
        agg.ingest(&failed(4, "d"));
        assert_eq!(agg.snapshot().kpis.failure_rate, Some(0.25));
    }

    #[test]
    fn scan_lifecycle_moves_through_requested_running_and_leaves_in_flight() {
        let (agg, _clock) = aggregator();
        agg.ingest(&requested(1, "s1"));
        let snap = agg.snapshot();
        assert_eq!(snap.kpis.scans_in_flight, 1);
        assert_eq!(snap.scans_in_flight[0].scan_id, "s1");
        assert_eq!(snap.scans_in_flight[0].status, ScanFlightStatus::Requested);

        agg.ingest(&started(2, "s1"));
        assert_eq!(
            agg.snapshot().scans_in_flight[0].status,
            ScanFlightStatus::Running
        );

        // `scan.requested` repetido tarde no degrada un escaneo en ejecución.
        agg.ingest(&requested(3, "s1"));
        assert_eq!(
            agg.snapshot().scans_in_flight[0].status,
            ScanFlightStatus::Running
        );

        agg.ingest(&completed(4, "s1"));
        assert_eq!(agg.snapshot().kpis.scans_in_flight, 0);
    }

    #[test]
    fn started_without_a_request_and_cancelled_scans_are_tracked_and_removed() {
        let (agg, _clock) = aggregator();
        agg.ingest(&started(1, "orphan"));
        assert_eq!(agg.snapshot().kpis.scans_in_flight, 1);
        agg.ingest(&event(
            2,
            "scan.cancelled",
            Some("u1"),
            Some("orphan"),
            json!({}),
        ));
        let snap = agg.snapshot();
        assert_eq!(snap.kpis.scans_in_flight, 0);
        // Cancelar no cuenta como completado ni fallido.
        assert_eq!(
            (
                snap.kpis.completed_last_window,
                snap.kpis.failed_last_window
            ),
            (0, 0)
        );
    }

    #[test]
    fn a_scan_whose_terminal_event_was_lost_expires_after_an_hour() {
        let (agg, clock) = aggregator();
        agg.ingest(&started(1, "lost"));
        clock.advance(Duration::from_secs(IN_FLIGHT_MAX_AGE_SECS as u64 - 1));
        assert_eq!(agg.snapshot().kpis.scans_in_flight, 1);
        clock.advance(Duration::from_secs(1));
        assert_eq!(agg.snapshot().kpis.scans_in_flight, 0);
    }

    #[test]
    fn in_flight_set_is_capped_and_evicts_the_oldest() {
        let (agg, clock) = aggregator();
        for i in 0..(MAX_IN_FLIGHT as u64 + 5) {
            agg.ingest(&started(i, &format!("scan-{i}")));
            clock.advance(Duration::from_millis(1));
        }
        let snap = agg.snapshot();
        assert_eq!(snap.scans_in_flight.len(), MAX_IN_FLIGHT);
        assert!(snap.scans_in_flight.iter().all(|s| s.scan_id != "scan-0"));
        assert!(snap
            .scans_in_flight
            .iter()
            .any(|s| s.scan_id == format!("scan-{}", MAX_IN_FLIGHT + 4)));
    }

    #[test]
    fn active_users_are_distinct_logins_minus_logouts_inside_the_window() {
        let (agg, clock) = aggregator();
        agg.ingest(&login(1, "a"));
        agg.ingest(&login(2, "a"));
        agg.ingest(&login(3, "b"));
        assert_eq!(
            agg.snapshot().kpis.active_users,
            2,
            "el mismo usuario cuenta una vez"
        );

        agg.ingest(&logout(4, "a"));
        assert_eq!(agg.snapshot().kpis.active_users, 1);

        agg.ingest(&login(5, "a"));
        assert_eq!(
            agg.snapshot().kpis.active_users,
            2,
            "un login posterior al logout reactiva"
        );

        clock.advance(Duration::from_secs(WINDOW_SECS));
        assert_eq!(
            agg.snapshot().kpis.active_users,
            0,
            "sin actividad dentro de la ventana"
        );
    }

    #[test]
    fn active_user_table_is_capped() {
        let (agg, _clock) = aggregator();
        for i in 0..(MAX_ACTIVE_USERS as u64 + 10) {
            agg.ingest(&login(i, &format!("user-{i}")));
        }
        assert_eq!(agg.snapshot().kpis.active_users, MAX_ACTIVE_USERS as u64);
    }

    #[test]
    fn rate_limit_hits_are_windowed() {
        let (agg, clock) = aggregator();
        agg.ingest(&ratelimit(1));
        agg.ingest(&ratelimit(2));
        assert_eq!(agg.snapshot().kpis.rate_limit_hits, 2);
        clock.advance(Duration::from_secs(WINDOW_SECS));
        assert_eq!(agg.snapshot().kpis.rate_limit_hits, 0);
    }

    #[test]
    fn critical_findings_are_newest_first_and_capped_at_fifty() {
        let (agg, _clock) = aggregator();
        for i in 0..(MAX_CRITICAL_FINDINGS as u64 + 7) {
            agg.ingest(&critical(i, &format!("scan-{i}")));
        }
        let findings = agg.snapshot().critical_findings;
        assert_eq!(findings.len(), MAX_CRITICAL_FINDINGS);
        assert_eq!(
            findings[0].scan_id,
            format!("scan-{}", MAX_CRITICAL_FINDINGS + 6)
        );
        assert_eq!(findings[0].port, 22);
        assert_eq!(findings[0].cve_id.as_deref(), Some("CVE-2023-38408"));
        assert_eq!(findings[0].severity, "critical");
    }

    #[test]
    fn event_log_keeps_the_last_hundred_with_only_envelope_fields_and_payload() {
        let (agg, _clock) = aggregator();
        for i in 0..(MAX_RECENT_EVENTS as u64 + 20) {
            agg.ingest(&login(i, "someone"));
        }
        let snap = agg.snapshot();
        assert_eq!(snap.recent_events.len(), MAX_RECENT_EVENTS);
        assert_eq!(
            snap.recent_events[0].event_id,
            format!("00000000-0000-4000-8000-{:012}", MAX_RECENT_EVENTS + 19)
        );

        let serialized = serde_json::to_value(&snap.recent_events[0]).unwrap();
        let mut keys: Vec<_> = serialized.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "actor_sub",
                "event_id",
                "event_type",
                "occurred_at",
                "payload",
                "source"
            ]
        );
    }

    #[test]
    fn malformed_records_are_counted_and_announced() {
        let (agg, _clock) = aggregator();
        let (_snap, mut rx) = agg.subscribe_with_snapshot();
        agg.record_malformed();
        agg.record_malformed();
        assert_eq!(agg.snapshot().kpis.malformed_records, 2);
        let delta = rx.try_recv().expect("delta de registro malformado");
        assert!(delta.event.is_none());
        assert_eq!(delta.kpis.malformed_records, 1);
    }

    #[test]
    fn a_redelivered_event_id_is_ignored() {
        let (agg, _clock) = aggregator();
        agg.ingest(&completed(1, "s1"));
        agg.ingest(&completed(1, "s1"));
        let snap = agg.snapshot();
        assert_eq!(snap.kpis.completed_last_window, 1);
        assert_eq!(snap.recent_events.len(), 1);
    }

    #[test]
    fn dedupe_memory_is_bounded() {
        let (agg, _clock) = aggregator();
        for i in 0..(DEDUPE_CAPACITY as u64 + 50) {
            agg.ingest(&login(i, "u"));
        }
        let state = agg.inner.lock().unwrap();
        assert_eq!(state.seen_order.len(), DEDUPE_CAPACITY);
        assert_eq!(state.seen_ids.len(), DEDUPE_CAPACITY);
    }

    #[test]
    fn deltas_carry_a_sequence_the_event_fresh_kpis_and_the_scan_change() {
        let (agg, _clock) = aggregator();
        let (snap, mut rx) = agg.subscribe_with_snapshot();
        assert_eq!(snap.seq, 0);

        agg.ingest(&requested(1, "s1"));
        agg.ingest(&critical(2, "s1"));
        agg.ingest(&completed(3, "s1"));

        let first = rx.try_recv().unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(first.event.as_ref().unwrap().event_type, "scan.requested");
        assert_eq!(first.kpis.scans_in_flight, 1);
        assert_eq!(
            first.scan_change,
            Some(ScanChange {
                scan_id: "s1".into(),
                status: ScanChangeStatus::Requested
            })
        );

        let second = rx.try_recv().unwrap();
        assert_eq!(second.critical_finding.as_ref().unwrap().port, 22);

        let third = rx.try_recv().unwrap();
        assert_eq!(third.seq, 3);
        assert_eq!(third.kpis.completed_last_window, 1);
        assert_eq!(
            third.scan_change,
            Some(ScanChange {
                scan_id: "s1".into(),
                status: ScanChangeStatus::Finished
            })
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn snapshot_and_receiver_are_taken_atomically() {
        let (agg, _clock) = aggregator();
        agg.ingest(&login(1, "a"));
        let (snap, mut rx) = agg.subscribe_with_snapshot();
        agg.ingest(&login(2, "b"));
        assert_eq!(snap.seq, 1);
        assert_eq!(
            rx.try_recv().unwrap().seq,
            2,
            "el primer delta es el siguiente al snapshot"
        );
    }

    #[test]
    fn a_slow_receiver_lags_instead_of_growing_memory() {
        let (agg, _clock) = aggregator();
        let (_snap, mut rx) = agg.subscribe_with_snapshot();
        for i in 0..(DELTA_CHANNEL_CAPACITY as u64 + 10) {
            agg.ingest(&login(i, &format!("u{i}")));
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Lagged(_))));
    }

    #[test]
    fn snapshot_serializes_with_the_documented_field_names() {
        let (agg, _clock) = aggregator();
        let value = serde_json::to_value(agg.snapshot()).unwrap();
        for key in [
            "seq",
            "generated_at",
            "window_seconds",
            "kpis",
            "scans_in_flight",
            "critical_findings",
            "recent_events",
        ] {
            assert!(value.get(key).is_some(), "falta `{key}`");
        }
        assert_eq!(value["window_seconds"], 900);
        assert_eq!(value["kpis"]["failure_rate"], Value::Null);
    }
}
