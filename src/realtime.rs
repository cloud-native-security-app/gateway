//! Registro de streams SSE activos por `scanId` y puente entre un evento
//! consumido del Broker ([`crate::broker`]) y los clientes SSE suscritos
//! (RF-07/RF-08, feature `scan_outcome_relay`).

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use axum::response::sse::Event;
use futures_util::stream::{self, Stream};
use tokio::sync::broadcast;

use crate::domain::ScanOutcomeEvent;

/// Capacidad del canal `broadcast` por `scan_id`: basta con un puñado de
/// eventos en vuelo (`started`/`completed`|`failed`) antes de que el/los
/// suscriptores los consuman — no es un búfer de histórico.
const CHANNEL_CAPACITY: usize = 16;

/// Registro en memoria de streams SSE activos por `scan_id` (el
/// `correlation_id` propio de este Gateway, ver
/// [`crate::domain::ScanOutcomeEvent::correlation_id`]), y puente entre el
/// consumidor de fondo de `gateway.scan-outcomes` ([`crate::broker`]) y esos
/// streams.
///
/// **Limitación de diseño, aceptada, no sobre-ingenierizada**: vive
/// únicamente en la memoria de este proceso (mismo patrón que
/// `auth::LoginStateStore`) — una entrada puede sobrevivir brevemente sin
/// receptores vivos (p. ej. el cliente SSE cerró la pestaña justo antes de
/// que el consumidor de fondo mirara ese `scan_id`) hasta el próximo evento
/// para ese `scan_id` o el cierre del propio stream. El coste de una entrada
/// huérfana es un `Sender` vacío en el `HashMap`, acotado por el número de
/// `scan_id` que de verdad han tenido un stream SSE alguna vez.
pub struct RealtimeRegistry {
    channels: RwLock<HashMap<String, broadcast::Sender<ScanOutcomeEvent>>>,
}

impl RealtimeRegistry {
    /// Registro vacío.
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
        }
    }

    /// Se suscribe a los eventos de `scan_id`, creando el canal si es la
    /// primera suscripción.
    fn subscribe(&self, scan_id: &str) -> broadcast::Receiver<ScanOutcomeEvent> {
        let mut channels = self
            .channels
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        channels
            .entry(scan_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    /// Empuja `event` a cualquier cliente SSE suscrito a
    /// `event.correlation_id()`. Si no hay ningún `Sender` registrado, o el
    /// `Sender` no tiene receptores vivos, el evento simplemente no tiene
    /// destinatario — no se bufferiza para suscriptores futuros.
    pub fn publish(&self, event: &ScanOutcomeEvent) {
        let channels = self
            .channels
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(sender) = channels.get(event.correlation_id()) {
            // `send` devuelve `Err` si no hay receptores vivos en ESTE
            // instante: no es un fallo real, es "nadie está escuchando ahora
            // mismo".
            let _ = sender.send(event.clone());
        }
    }

    /// Limpia `scan_id` del registro si su `Sender` ya no tiene ningún
    /// receptor vivo. Llamado desde el `Drop` del guard privado
    /// `SubscriptionGuard` de este módulo al terminar (ordenadamente o por
    /// desconexión del cliente) un stream SSE.
    fn remove_if_orphaned(&self, scan_id: &str) {
        let mut channels = self
            .channels
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(sender) = channels.get(scan_id) {
            if sender.receiver_count() == 0 {
                channels.remove(scan_id);
            }
        }
    }

    /// Construye el `Stream` SSE que emite cada evento nuevo de `scan_id`
    /// hasta alcanzar un estado terminal (`completed`/`failed`), momento en
    /// el que el propio `Stream` termina (`None`) — cierre ordenado, sin
    /// esperar indefinidamente. También termina (sin emitir un evento
    /// terminal) si el productor de este `scan_id` desaparece antes de
    /// llegar a un estado terminal.
    ///
    /// El registro de este `scan_id` se limpia (si queda huérfano) tanto al
    /// cerrarse ordenadamente el stream como si el cliente se desconecta
    /// antes (en ambos casos el `Stream` devuelto se termina de dropear,
    /// ver el guard privado `SubscriptionGuard` de este módulo).
    pub fn subscribe_stream(
        self: &Arc<Self>,
        scan_id: String,
    ) -> impl Stream<Item = Result<Event, Infallible>> {
        let receiver = self.subscribe(&scan_id);
        let guard = SubscriptionGuard {
            registry: Arc::clone(self),
            scan_id,
        };

        stream::unfold(Some((receiver, guard)), |state| async move {
            let (mut receiver, guard) = state?;
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        let is_terminal = event.is_terminal();
                        let sse_event = to_sse_event(&event);
                        let next_state = if is_terminal {
                            None
                        } else {
                            Some((receiver, guard))
                        };
                        return Some((Ok(sse_event), next_state));
                    }
                    // Se perdieron eventos intermedios (receptor lento): no
                    // es fatal, seguimos escuchando el siguiente.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    // El `Sender` se soltó (este `scan_id` nunca tuvo, o ya
                    // no tiene, ningún productor) -> fin ordenado del
                    // stream.
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
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
/// [`ScanOutcomeEvent`] siempre serializa), se degrada a un evento explícito
/// `event: error` en vez de tumbar el stream (`Stream<Item = Result<_,
/// Infallible>>` no tiene forma sana de propagar un error real).
fn to_sse_event(event: &ScanOutcomeEvent) -> Event {
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
}
