//! Registro de streams SSE activos por `scanId` y puente entre un evento
//! consumido del Broker ([`crate::broker`]) y los clientes SSE suscritos
//! (RF-07/RF-08, features `scan_outcome_relay` y `scan_sse_resilience`).

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{self, Stream};
use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::domain::{ScanLiveEvent, ScanOutcomeEvent};

/// Capacidad del canal `broadcast` por `scan_id`: basta con un puñado de
/// eventos en vuelo (`started`/terminal) antes de que el/los suscriptores los
/// consuman — no es un búfer de histórico.
const CHANNEL_CAPACITY: usize = 16;

/// Máximo de `scan_id` con último evento recordado; al superarlo se descarta
/// el más antiguo.
pub const DEFAULT_MAX_CACHED_SCANS: usize = 1024;

/// Vida de un evento terminal recordado (tiempo de sobra para que el
/// navegador reconecte o recargue la página).
pub const DEFAULT_TERMINAL_TTL: Duration = Duration::from_secs(15 * 60);

/// Intervalo de los comentarios SSE de keep-alive: menor que el
/// `idle_timeout` del balanceador, para que no cierre el stream en silencio.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Envuelve `stream` en una respuesta SSE con comentarios `:` periódicos
/// (invisibles para los `onmessage` de `EventSource`).
pub fn sse_with_keep_alive<S>(stream: S, interval: Duration) -> Sse<S>
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    Sse::new(stream).keep_alive(KeepAlive::new().interval(interval))
}

/// Último evento recordado de un `scan_id`.
struct CachedEvent {
    event: ScanLiveEvent,
    /// Orden de inserción, para descartar el más antiguo.
    seq: u64,
    /// Instante en que el evento terminal fue recordado (`None` si no lo es).
    terminal_since: Option<Instant>,
}

#[derive(Default)]
struct Inner {
    channels: HashMap<String, broadcast::Sender<ScanLiveEvent>>,
    last: HashMap<String, CachedEvent>,
    next_seq: u64,
}

/// Registro en memoria de streams SSE activos por `scan_id` (el
/// `correlation_id` propio de este Gateway, ver
/// [`crate::domain::ScanOutcomeEvent::correlation_id`]), y puente entre el
/// consumidor de fondo de `gateway.scan-outcomes` ([`crate::broker`]) y esos
/// streams.
///
/// Recuerda el último evento de cada `scan_id` aunque nadie esté suscrito: un
/// suscriptor tardío (reconexión del navegador, recarga de la página) recibe
/// primero ese evento y luego los vivos; si es terminal, el stream lo emite y
/// termina. La memoria está acotada: como máximo `max_cached` scans (se
/// descarta el más antiguo) y los terminales expiran tras `terminal_ttl`.
///
/// **Limitación de diseño, aceptada**: vive solo en la memoria de este
/// proceso (mismo patrón que `auth::LoginStateStore`); tras un reinicio no hay
/// nada que reenviar y el navegador debe consultar el histórico.
///
/// Un único `Mutex` protege canales y caché: publicar y "suscribirse + leer el
/// último" son atómicos entre sí, así que un evento nunca se pierde ni se
/// duplica entre ambos pasos.
pub struct RealtimeRegistry {
    inner: Mutex<Inner>,
    max_cached: usize,
    terminal_ttl: Duration,
}

impl RealtimeRegistry {
    /// Registro vacío con los límites por defecto.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_CACHED_SCANS, DEFAULT_TERMINAL_TTL)
    }

    /// Registro vacío con límites explícitos (tests).
    pub fn with_limits(max_cached: usize, terminal_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_cached: max_cached.max(1),
            terminal_ttl,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Atómicamente: último evento vigente de `scan_id` y, si no es terminal,
    /// un receptor de los siguientes.
    fn subscribe(
        &self,
        scan_id: &str,
    ) -> (
        Option<ScanLiveEvent>,
        Option<broadcast::Receiver<ScanLiveEvent>>,
    ) {
        let mut inner = self.lock();
        let now = Instant::now();
        let ttl = self.terminal_ttl;
        let expired = |c: &CachedEvent| {
            c.terminal_since
                .is_some_and(|since| now.duration_since(since) >= ttl)
        };
        if inner.last.get(scan_id).is_some_and(expired) {
            inner.last.remove(scan_id);
        }
        let replay = inner.last.get(scan_id).map(|c| c.event.clone());
        if replay.as_ref().is_some_and(ScanLiveEvent::is_terminal) {
            return (replay, None);
        }
        let receiver = inner
            .channels
            .entry(scan_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe();
        (replay, Some(receiver))
    }

    /// Empuja `event` tal cual lo publicó el Broker (sin cancelación).
    pub fn publish(&self, event: &ScanOutcomeEvent) {
        self.publish_live(ScanLiveEvent::from_outcome(event, false));
    }

    /// Recuerda `event` como último de su `scan_id` y lo empuja a los
    /// suscriptores vivos, si hay.
    pub fn publish_live(&self, event: ScanLiveEvent) {
        let mut inner = self.lock();
        let now = Instant::now();
        let ttl = self.terminal_ttl;
        inner.last.retain(|_, c| {
            c.terminal_since
                .is_none_or(|since| now.duration_since(since) < ttl)
        });

        let scan_id = event.correlation_id().to_string();
        let already_terminal = inner
            .last
            .get(&scan_id)
            .is_some_and(|c| c.event.is_terminal());
        // Un duplicado tardío (SQS entrega al menos una vez) no debe
        // "des-terminar" un escaneo ya cerrado.
        if !(already_terminal && !event.is_terminal()) {
            if !inner.last.contains_key(&scan_id) && inner.last.len() >= self.max_cached {
                let oldest = inner
                    .last
                    .iter()
                    .min_by_key(|(_, c)| c.seq)
                    .map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    inner.last.remove(&oldest);
                }
            }
            let seq = inner.next_seq;
            inner.next_seq += 1;
            let terminal_since = event.is_terminal().then_some(now);
            inner.last.insert(
                scan_id.clone(),
                CachedEvent {
                    event: event.clone(),
                    seq,
                    terminal_since,
                },
            );
        }

        if let Some(sender) = inner.channels.get(&scan_id) {
            // `Err` = nadie escuchando ahora mismo; no es un fallo.
            let _ = sender.send(event);
        }
    }

    /// Limpia el canal de `scan_id` si ya no tiene receptores vivos (la
    /// caché del último evento se conserva). Llamado desde el `Drop` de
    /// `SubscriptionGuard`.
    fn remove_if_orphaned(&self, scan_id: &str) {
        let mut inner = self.lock();
        if inner
            .channels
            .get(scan_id)
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            inner.channels.remove(scan_id);
        }
    }

    /// Construye el `Stream` SSE de `scan_id`: primero el último evento
    /// recordado (si lo hay), luego cada evento nuevo, hasta un estado
    /// terminal (`completed`/`failed`/`cancelled`), momento en el que el
    /// `Stream` termina (`None`). Si el último evento recordado ya es
    /// terminal, se emite y el stream termina. Un `scan_id` sin eventos
    /// recordados (desconocido o expirado) no emite nada y queda abierto. También
    /// termina si el productor desaparece antes de un estado terminal.
    ///
    /// El canal se limpia (si queda huérfano) al soltarse el stream, sea por
    /// cierre ordenado o por desconexión del cliente (`SubscriptionGuard`).
    pub fn subscribe_stream(
        self: &Arc<Self>,
        scan_id: String,
    ) -> impl Stream<Item = Result<Event, Infallible>> {
        let (replay, receiver) = self.subscribe(&scan_id);
        let guard = receiver.is_some().then(|| SubscriptionGuard {
            registry: Arc::clone(self),
            scan_id,
        });

        stream::unfold(Some((replay, receiver, guard)), |state| async move {
            let (mut pending, mut receiver, guard) = state?;
            let event = match pending.take() {
                Some(event) => event,
                None => loop {
                    match receiver.as_mut()?.recv().await {
                        Ok(event) => break event,
                        // Receptor lento: seguimos con el siguiente.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        // Sin productor -> fin ordenado.
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                },
            };
            let sse_event = to_sse_event(&event);
            let next = (!event.is_terminal()).then_some((None, receiver, guard));
            Some((Ok(sse_event), next))
        })
    }
}

impl Default for RealtimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializa `event` como un [`Event`] SSE (`data: <json>\n\n`). Nunca falla
/// de forma observable: si la serialización fallara (no debería, dado que
/// [`ScanLiveEvent`] siempre serializa), se degrada a un evento explícito
/// `event: error` en vez de tumbar el stream (`Stream<Item = Result<_,
/// Infallible>>` no tiene forma sana de propagar un error real).
fn to_sse_event(event: &ScanLiveEvent) -> Event {
    Event::default().json_data(event).unwrap_or_else(|_| {
        Event::default()
            .event("error")
            .data("no se pudo serializar el evento de escaneo")
    })
}

/// Limpia (best-effort) la entrada de [`RealtimeRegistry`] asociada a un
/// `scan_id` cuando el stream SSE que la usaba termina, sea ordenadamente
/// (estado terminal alcanzado) o porque el cliente se desconectó antes.
struct SubscriptionGuard {
    registry: Arc<RealtimeRegistry>,
    scan_id: String,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.registry.remove_if_orphaned(&self.scan_id);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_util::StreamExt;

    use super::*;

    fn started(scan_id: &str) -> ScanOutcomeEvent {
        ScanOutcomeEvent::Started {
            correlation_id: scan_id.to_string(),
        }
    }

    fn failed(scan_id: &str) -> ScanOutcomeEvent {
        ScanOutcomeEvent::Failed {
            correlation_id: scan_id.to_string(),
            reason: "host inalcanzable".to_string(),
        }
    }

    #[tokio::test]
    async fn relays_events_in_order_and_closes_on_terminal_state() {
        let registry = Arc::new(RealtimeRegistry::new());
        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));

        registry.publish(&started("scan-1"));
        registry.publish(&failed("scan-1"));

        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no debe colgarse")
            .expect("debe llegar el primer evento")
            .expect("Infallible");
        let second = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no debe colgarse")
            .expect("debe llegar el segundo evento")
            .expect("Infallible");

        assert!(format!("{first:?}").contains("started"));
        assert!(format!("{second:?}").contains("failed"));

        let after_terminal = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no debe colgarse tras el evento terminal");
        assert!(
            after_terminal.is_none(),
            "el stream debe cerrarse tras el estado terminal"
        );
    }

    #[tokio::test]
    async fn publish_without_any_subscriber_does_not_panic() {
        let registry = RealtimeRegistry::new();

        registry.publish(&started("scan-nadie-escucha"));
    }

    #[tokio::test]
    async fn events_for_a_different_scan_id_are_not_relayed() {
        let registry = Arc::new(RealtimeRegistry::new());
        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-a".to_string()));

        registry.publish(&started("scan-b"));
        registry.publish(&failed("scan-a"));

        let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no debe colgarse")
            .expect("debe llegar el evento de scan-a")
            .expect("Infallible");

        assert!(format!("{event:?}").contains("failed"));
    }

    async fn next_event(
        stream: &mut (impl Stream<Item = Result<Event, Infallible>> + Unpin),
    ) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no debe colgarse")
            .map(|event| format!("{:?}", event.expect("Infallible")))
    }

    #[tokio::test]
    async fn late_subscriber_after_terminal_event_gets_it_and_the_stream_ends() {
        let registry = Arc::new(RealtimeRegistry::new());
        registry.publish(&started("scan-1"));
        registry.publish(&failed("scan-1"));

        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));

        let replayed = next_event(&mut stream)
            .await
            .expect("debe reenviarse el terminal");
        assert!(replayed.contains("failed"));
        assert!(next_event(&mut stream).await.is_none(), "debe cerrarse");
    }

    #[tokio::test]
    async fn late_subscriber_mid_scan_gets_started_then_live_events() {
        let registry = Arc::new(RealtimeRegistry::new());
        registry.publish(&started("scan-1"));

        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));
        registry.publish(&failed("scan-1"));

        let first = next_event(&mut stream).await.expect("started reenviado");
        let second = next_event(&mut stream).await.expect("failed en vivo");
        assert!(first.contains("started"));
        assert!(second.contains("failed"));
        assert!(next_event(&mut stream).await.is_none());
    }

    #[tokio::test]
    async fn subscriber_to_an_unknown_scan_gets_nothing_and_stays_open() {
        let registry = Arc::new(RealtimeRegistry::new());
        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-x".to_string()));

        let waited = tokio::time::timeout(Duration::from_millis(50), stream.next()).await;
        assert!(waited.is_err(), "sin eventos el stream debe seguir abierto");
    }

    #[tokio::test]
    async fn cancelled_event_is_terminal_and_serialized_with_its_status() {
        let registry = Arc::new(RealtimeRegistry::new());
        registry.publish_live(ScanLiveEvent::from_outcome(&failed("scan-1"), true));

        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));

        let replayed = next_event(&mut stream).await.expect("cancelled");
        assert!(
            replayed.contains(r#"\"status\":\"cancelled\""#),
            "{replayed}"
        );
        assert!(replayed.contains("host inalcanzable"));
        assert!(next_event(&mut stream).await.is_none());
    }

    #[tokio::test]
    async fn late_terminal_does_not_get_overwritten_by_a_duplicate_started() {
        let registry = Arc::new(RealtimeRegistry::new());
        registry.publish(&failed("scan-1"));
        registry.publish(&started("scan-1"));

        let mut stream = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));

        assert!(next_event(&mut stream)
            .await
            .expect("terminal")
            .contains("failed"));
    }

    #[tokio::test]
    async fn cache_keeps_at_most_max_entries_evicting_the_oldest() {
        let registry = Arc::new(RealtimeRegistry::with_limits(2, Duration::from_secs(60)));
        registry.publish(&started("a"));
        registry.publish(&started("b"));
        registry.publish(&started("c"));

        let mut evicted = std::pin::pin!(registry.subscribe_stream("a".to_string()));
        let waited = tokio::time::timeout(Duration::from_millis(50), evicted.next()).await;
        assert!(
            waited.is_err(),
            "a fue descartado: no hay nada que reenviar"
        );

        let mut kept = std::pin::pin!(registry.subscribe_stream("c".to_string()));
        assert!(next_event(&mut kept)
            .await
            .expect("c sigue")
            .contains("started"));
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_entries_expire_after_the_ttl_but_not_before() {
        let registry = Arc::new(RealtimeRegistry::with_limits(8, Duration::from_secs(60)));
        registry.publish(&failed("scan-1"));

        tokio::time::advance(Duration::from_secs(59)).await;
        let mut before = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));
        assert!(next_event(&mut before).await.is_some(), "aún vigente");

        tokio::time::advance(Duration::from_secs(2)).await;
        let mut after = std::pin::pin!(registry.subscribe_stream("scan-1".to_string()));
        let waited = tokio::time::timeout(Duration::from_millis(50), after.next()).await;
        assert!(
            waited.is_err(),
            "expirado: nada que reenviar, stream abierto"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_terminal_entries_are_purged_on_the_next_publish() {
        let registry = Arc::new(RealtimeRegistry::with_limits(8, Duration::from_secs(60)));
        registry.publish(&failed("old"));
        tokio::time::advance(Duration::from_secs(61)).await;
        registry.publish(&started("new"));

        assert_eq!(registry.lock().last.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn sse_response_emits_keep_alive_comments_while_idle() {
        use axum::response::IntoResponse;

        let idle = stream::pending::<Result<Event, Infallible>>();
        let response = sse_with_keep_alive(idle, KEEP_ALIVE_INTERVAL).into_response();
        let mut body = response.into_body().into_data_stream();

        let chunk = tokio::time::timeout(Duration::from_secs(16), body.next())
            .await
            .expect("debe llegar un keep-alive antes de 16 s")
            .expect("el stream sigue abierto")
            .expect("chunk");
        assert!(
            chunk.starts_with(b":"),
            "el keep-alive es un comentario SSE: {chunk:?}"
        );
    }
}
