//! Consumidor SQS de `gateway-scan-outcomes` (tarea MSG-GW-03), que
//! reemplazó al consumidor AMQP de RabbitMQ (cableado en [`crate::wiring`]).
//!
//! Decisiones de diseño:
//!
//! - **Borrado tras `handle`** (decisión del usuario, 2026-10-19): un mensaje
//!   válido se borra de la cola solo cuando `handler.handle` ya retornó. Si el
//!   proceso muere a mitad, SQS lo reentrega al vencer el `VisibilityTimeout`
//!   y, tras 3 recepciones, la `RedrivePolicy` de la cola lo mueve a la DLQ.
//!   El handler debe tolerar duplicados. (El consumidor AMQP hacía `ack`
//!   antes de `handle`.)
//! - **Malformados**: paridad con `nack(requeue=false)` del Broker (decisión
//!   Q5): se reenvía el cuerpo original a la DLQ con un `SendMessage`
//!   explícito (conservando el atributo `routing_key`) y luego se borra de la
//!   cola fuente. Si el envío a la DLQ falla no se borra: lo resuelve el
//!   redrive. Solo se loggea error, `routing_key` y largo; nunca el cuerpo.
//! - **Errores transitorios de recepción**: se loggean y se reintenta con
//!   backoff exponencial (1 s hasta 30 s), sin salir nunca del bucle salvo por
//!   shutdown; reemplaza el bucle de reconexión AMQP.
//! - **Shutdown**: un [`CancellationToken`] compite contra el long poll y el
//!   backoff, así que `run` vuelve de inmediato; un `handle` en curso termina
//!   antes de retornar y los mensajes restantes del lote no procesados
//!   simplemente reaparecen al vencer su visibilidad.
//!
//! Las credenciales salen de la cadena de proveedores por defecto de AWS.

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_sqs::error::DisplayErrorContext;
use aws_sdk_sqs::types::{Message, MessageAttributeValue};
use aws_sdk_sqs::Client;
use tokio_util::sync::CancellationToken;

use crate::broker::{BrokerError, ScanOutcomeHandler};
use crate::domain::ScanOutcomeEvent;
use crate::sns::ROUTING_KEY_ATTRIBUTE;

/// Espera máxima del long polling de `ReceiveMessage`, en segundos.
const WAIT_TIME_SECONDS: i32 = 20;
/// Máximo de mensajes por `ReceiveMessage` (tope de SQS).
const MAX_MESSAGES: i32 = 10;
/// Primer backoff tras un error de recepción.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Tope del backoff exponencial.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Consumidor de la cola SQS de resultados de escaneo, con su DLQ para los
/// mensajes malformados.
#[derive(Debug, Clone)]
pub struct SqsScanOutcomeConsumer {
    client: Client,
    queue_url: String,
    dlq_url: String,
}

impl SqsScanOutcomeConsumer {
    /// Construye el consumidor sobre un `client` ya configurado (los tests
    /// inyectan uno apuntando a LocalStack).
    pub fn from_client(client: Client, queue_url: String, dlq_url: String) -> Self {
        Self {
            client,
            queue_url,
            dlq_url,
        }
    }

    /// Construye el consumidor con la cadena de credenciales por defecto de
    /// AWS, la `region` indicada y, opcionalmente, un `endpoint_url` (solo
    /// LocalStack).
    pub async fn connect(
        region: &str,
        endpoint_url: Option<&str>,
        queue_url: String,
        dlq_url: String,
    ) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(url) = endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let shared = loader.load().await;
        Self::from_client(Client::new(&shared), queue_url, dlq_url)
    }

    /// Consume la cola hasta que `shutdown` se cancele (ver la nota de diseño
    /// del módulo para borrado, malformados, backoff y shutdown).
    pub async fn run(self, handler: Arc<dyn ScanOutcomeHandler>, shutdown: CancellationToken) {
        let mut backoff = BACKOFF_INITIAL;
        while !shutdown.is_cancelled() {
            let receive = self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .wait_time_seconds(WAIT_TIME_SECONDS)
                .max_number_of_messages(MAX_MESSAGES)
                .message_attribute_names("All")
                .send();
            let result = tokio::select! {
                _ = shutdown.cancelled() => break,
                result = receive => result,
            };
            match result {
                Ok(output) => {
                    backoff = BACKOFF_INITIAL;
                    for message in output.messages.unwrap_or_default() {
                        if shutdown.is_cancelled() {
                            break;
                        }
                        self.process(&*handler, message).await;
                    }
                }
                Err(err) => {
                    tracing::error!(
                        error = %DisplayErrorContext(&err),
                        retry_in_secs = backoff.as_secs(),
                        "error recibiendo de la cola SQS de scan-outcomes; reintentando"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = next_backoff(backoff);
                }
            }
        }
        tracing::info!("consumidor SQS de scan-outcomes detenido");
    }

    async fn process(&self, handler: &dyn ScanOutcomeHandler, message: Message) {
        let Some(receipt_handle) = message.receipt_handle() else {
            tracing::error!("mensaje SQS sin receipt handle descartado de la iteración");
            return;
        };
        let body = message.body().unwrap_or_default();
        match serde_json::from_str::<ScanOutcomeEvent>(body) {
            Ok(event) => {
                handler.handle(event).await;
                if let Err(err) = self.delete(&self.queue_url, receipt_handle).await {
                    tracing::error!(
                        error = %err,
                        "no se pudo borrar un ScanOutcome ya procesado; SQS lo reentregará"
                    );
                }
            }
            Err(parse_err) => {
                tracing::warn!(
                    error = %parse_err,
                    routing_key = routing_key_of(&message).unwrap_or("<ausente>"),
                    payload_len = body.len(),
                    "mensaje malformado en la cola SQS de scan-outcomes enviado a la DLQ"
                );
                if let Err(err) = self.send_to_dlq(&message, body).await {
                    tracing::error!(
                        error = %err,
                        "no se pudo enviar un mensaje malformado a la DLQ; se deja en la cola"
                    );
                    return;
                }
                if let Err(err) = self.delete(&self.queue_url, receipt_handle).await {
                    tracing::error!(
                        error = %err,
                        "no se pudo borrar un mensaje malformado ya enviado a la DLQ"
                    );
                }
            }
        }
    }

    async fn send_to_dlq(&self, message: &Message, body: &str) -> Result<(), BrokerError> {
        let mut request = self
            .client
            .send_message()
            .queue_url(&self.dlq_url)
            .message_body(body);
        if let Some(routing_key) = routing_key_of(message) {
            let attribute = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(routing_key)
                .build()
                .expect("data_type está presente");
            request = request.message_attributes(ROUTING_KEY_ATTRIBUTE, attribute);
        }
        request
            .send()
            .await
            .map_err(|source| BrokerError::SqsFailed {
                queue: self.dlq_url.clone(),
                source: Box::new(source),
            })?;
        Ok(())
    }

    async fn delete(&self, queue_url: &str, receipt_handle: &str) -> Result<(), BrokerError> {
        self.client
            .delete_message()
            .queue_url(queue_url)
            .receipt_handle(receipt_handle)
            .send()
            .await
            .map_err(|source| BrokerError::SqsFailed {
                queue: queue_url.to_string(),
                source: Box::new(source),
            })?;
        Ok(())
    }
}

/// Valor del atributo `routing_key` del mensaje, si existe.
fn routing_key_of(message: &Message) -> Option<&str> {
    message
        .message_attributes()?
        .get(ROUTING_KEY_ATTRIBUTE)?
        .string_value()
}

/// Siguiente espera del backoff: el doble, con tope en [`BACKOFF_MAX`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_and_caps_at_thirty() {
        let mut d = BACKOFF_INITIAL;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
    }

    #[test]
    fn routing_key_is_extracted_when_present() {
        let attr = MessageAttributeValue::builder()
            .data_type("String")
            .string_value("scan.outcome.failed")
            .build()
            .unwrap();
        let with = Message::builder()
            .message_attributes(ROUTING_KEY_ATTRIBUTE, attr)
            .build();
        assert_eq!(routing_key_of(&with), Some("scan.outcome.failed"));
        assert_eq!(routing_key_of(&Message::builder().build()), None);
    }
}
