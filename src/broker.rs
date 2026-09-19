//! Cliente `lapin` sobre AMQPS: publicación de `ScanRequest`/
//! `ScanCancellation` y consumo de `gateway.scan-outcomes`.
//!
//! La feature `scan_submission` implementó
//! [`publish_scan_request`](ScanRequestPublisher::publish_scan_request); la
//! feature `scan_outcome_relay` añadió [`BrokerConsumer`], el consumidor de
//! `gateway.scan-outcomes`; la feature `scan_history_and_cancellation` añade
//! [`publish_scan_cancellation`](ScanRequestPublisher::publish_scan_cancellation)
//! al mismo trait [`ScanRequestPublisher`] (en vez de uno nuevo) para no
//! introducir un segundo campo en `AppState`/otro doble de prueba por cada
//! test de features anteriores que ya construyen un `AppState` completo —
//! ambos métodos comparten la misma conexión/canal AMQPS del usuario
//! `gateway`, que ya tiene permiso `write` sobre `scan.requests` **y**
//! `scan.cancellations` (ver `docs/security-scope.md`).
//!
//! ## Decisiones de diseño
//!
//! - **`lapin` 2.5.5, no 4.x**: `Cargo.lock` de este repo fija `lapin`
//!   2.5.5, con una API de conexión distinta a la que documenta el repo
//!   hermano `broker/` (que usa `lapin` 4.x). Ver
//!   `progress/explore_lapin_publish.md`/`progress/explore_lapin_consume.md`
//!   para el detalle verificado contra el código fuente real de esta
//!   versión.
//! - **No se declara topología**: el usuario RabbitMQ `gateway` (definido en
//!   `broker/rabbitmq/definitions.json`) solo tiene permiso `write` sobre
//!   `scan.requests`/`scan.cancellations` y `read` sobre
//!   `gateway.scan-outcomes` (`configure: "^$"`) — este módulo solo llama a
//!   `basic_publish`/`basic_consume`, nunca a `exchange_declare`/
//!   `queue_declare`/`queue_bind` (ver `docs/architecture.md` §"Qué NO
//!   hacer").
//! - **Confirms del Broker**: el canal del publicador activa
//!   `confirm_select` una sola vez al conectar, y
//!   [`BrokerPublisher::publish_scan_request`] espera el ack/nack real (no
//!   solo el envío del frame) antes de devolver éxito. Trade-off
//!   documentado: RNF-04 exige que `POST /api/scans` responda en <500ms, no
//!   "instantáneamente"; un ack de RabbitMQ en la misma subred privada añade
//!   típicamente un solo dígito de milisegundos, muy por debajo de ese
//!   presupuesto, y es lo único que permite distinguir "el frame se envió"
//!   de "el Broker aceptó el mensaje" — distinción que necesita el criterio
//!   de aceptación de `scan_submission` sobre marcar `Fallido` un histórico
//!   cuyo `ScanRequest` no llegó a publicarse. Ver
//!   `progress/explore_lapin_publish.md` §4 para el análisis completo. El
//!   canal del consumidor no activa `confirm_select` (es específico de
//!   publicar, no de consumir).
//! - **Sin reconexión automática**: `lapin` 2.5.5 no reconecta solo (ver
//!   `progress/explore_lapin_publish.md` §3.3 y
//!   `progress/explore_lapin_consume.md` §2.2). Ni el publicador ni
//!   [`BrokerConsumer::run`] implementan lógica de reconexión: si la
//!   conexión/canal AMQPS se cae, el publicador reporta [`BrokerError`] en
//!   la próxima publicación, y la tarea de fondo del consumidor loggea el
//!   fin del stream y termina (`return`), sin reintentar por su cuenta. El
//!   relay de avance en tiempo real (RF-07/RF-08) es una capa de UX
//!   (progreso en vivo por SSE), no la vía de registro autoritativo del
//!   resultado de un escaneo (`ms-analisis` lo consume de forma
//!   independiente) — construir aquí un supervisor con backoff/reintentos
//!   sería sobre-ingeniería para esta feature; si la caída del relay se
//!   considera inaceptable en producción, la mejora natural es que el
//!   **proceso completo** se reinicie (orquestador/`systemd`/Kubernetes),
//!   no que este módulo reimplemente su propio supervisor de reconexión
//!   AMQP.
//! - **Mensaje malformado -> `nack(requeue: false)`, nunca `ack` ni
//!   `nack(requeue: true)`**: un mensaje que no decodifica contra
//!   [`crate::domain::ScanOutcomeEvent`] es un fallo permanente (el
//!   `payload` no cambia entre reintentos), así que se descarta
//!   inmediatamente hacia `gateway.scan-outcomes.dlq` (ya aprovisionada por
//!   `broker/rabbitmq/definitions.json`) en vez de reintentarlo o
//!   descartarlo sin rastro. Ver `progress/explore_lapin_consume.md` §3 para
//!   el análisis completo (incluida la nota empírica de por qué
//!   `nack(requeue: true)` no dispararía `x-delivery-limit` contra este
//!   Broker real).

use std::sync::Arc;

use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
    ConfirmSelectOptions,
};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::domain::ScanOutcomeEvent;

/// Exchange donde este Gateway publica cada `ScanRequest` (topic, ya
/// declarado por `broker/rabbitmq/definitions.json` — no se redeclara
/// aquí).
pub const EXCHANGE_SCAN_REQUESTS: &str = "scan.requests";

/// Routing key con la que este Gateway publica cada `ScanRequest`.
pub const ROUTING_KEY_SCAN_REQUEST: &str = "scan.request";

/// Exchange donde este Gateway publica cada `ScanCancellation` (topic, ya
/// declarado por `broker/rabbitmq/definitions.json` — no se redeclara aquí,
/// feature `scan_history_and_cancellation`).
pub const EXCHANGE_SCAN_CANCELLATIONS: &str = "scan.cancellations";

/// Routing key con la que este Gateway publica cada `ScanCancellation`.
pub const ROUTING_KEY_SCAN_CANCELLATION: &str = "scan.cancellation";

/// Cola de la que este Gateway consume cada [`ScanOutcomeEvent`] (bindeada a
/// `scan.outcome.#` en `broker/rabbitmq/definitions.json` — no se redeclara
/// aquí, ver [`BrokerConsumer`]).
pub const QUEUE_GATEWAY_SCAN_OUTCOMES: &str = "gateway.scan-outcomes";

/// Identificador (`consumer_tag`) con el que este Gateway se registra como
/// consumidor de [`QUEUE_GATEWAY_SCAN_OUTCOMES`].
const CONSUMER_TAG: &str = "gateway-scan-outcome-relay";

/// Mensaje publicado en [`EXCHANGE_SCAN_REQUESTS`] (routing key
/// [`ROUTING_KEY_SCAN_REQUEST`]), consumido por `ms-nmap`. Shape copiado
/// literalmente de `broker/contracts/scan-request.schema.json` (6 campos,
/// todos requeridos, `additionalProperties: false` en el schema — este
/// `struct` no añade ni omite ninguno).
///
/// `ssh_credentials_ref` transporta una credencial SSH **real** (ver
/// `docs/security-scope.md`): este tipo implementa `Debug` a mano para
/// redactarla, en vez de derivarlo, de modo que un `tracing::debug!(?req)`
/// accidental nunca la exponga.
#[derive(Clone, Serialize)]
pub struct ScanRequest {
    /// Identificador de correlación de la solicitud, generado por este
    /// Gateway antes de cualquier llamada externa (RF-04).
    pub correlation_id: String,
    /// Dirección IP (o, si el objetivo era un rango CIDR ya validado por
    /// [`crate::domain::ScanSubmission`], la cadena tal cual se validó)
    /// objetivo del escaneo.
    pub ip: String,
    /// Usuario de red resuelto por `ms-usuarios` para este objetivo.
    pub network_user: String,
    /// Credencial SSH real resuelta por `ms-usuarios` para este objetivo.
    /// Nunca se loggea (ver `docs/security-scope.md`).
    pub ssh_credentials_ref: String,
    /// Si el usuario de red resuelto tiene privilegios `sudo` en el
    /// objetivo.
    pub has_sudo: bool,
    /// Identidad (ya verificada por este Gateway) de quien solicitó el
    /// escaneo.
    pub requested_by: String,
}

impl std::fmt::Debug for ScanRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanRequest")
            .field("correlation_id", &self.correlation_id)
            .field("ip", &self.ip)
            .field("network_user", &self.network_user)
            .field("ssh_credentials_ref", &"[REDACTED]")
            .field("has_sudo", &self.has_sudo)
            .field("requested_by", &self.requested_by)
            .finish()
    }
}

/// Mensaje publicado en [`EXCHANGE_SCAN_CANCELLATIONS`] (routing key
/// [`ROUTING_KEY_SCAN_CANCELLATION`]), consumido por `ms-nmap`. Shape copiado
/// literalmente de `broker/contracts/scan-cancellation.schema.json` (2
/// campos, ambos `string`, requeridos, `additionalProperties: false` en el
/// schema — este `struct` no añade ni omite ninguno).
///
/// No transporta ninguna credencial (a diferencia de [`ScanRequest`]), así
/// que puede derivar `Debug` sin necesidad de redactar nada.
#[derive(Debug, Clone, Serialize)]
pub struct ScanCancellation {
    /// El `correlation_id` del `ScanRequest` cuyo escaneo se quiere
    /// cancelar: el `scanId` propio de este Gateway, el mismo que generó
    /// `POST /api/scans` (feature `scan_submission`) — nunca el `scan_id`
    /// que asigna `ms-usuarios`.
    pub correlation_id: String,
    /// Identidad (ya verificada por este Gateway) de quien solicitó la
    /// cancelación — nunca un identificador reenviado sin verificar (ver
    /// `docs/security-scope.md`).
    pub requested_by: String,
}

/// Errores al comunicarse con el Broker desde este Gateway (publicar o
/// consumir).
///
/// Ninguna variante incluye la credencial AMQPS ni el cuerpo completo de un
/// `ScanRequest` (`ssh_credentials_ref`) en su mensaje (`docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// No se pudo conectar (o crear canal) contra el Broker por AMQPS.
    #[error("no se pudo conectar al Broker (AMQPS)")]
    ConnectionFailed(#[source] lapin::Error),
    /// No se pudo publicar en el exchange indicado.
    #[error("no se pudo publicar en el exchange '{exchange}'")]
    PublishFailed {
        /// Exchange contra el que se intentó publicar.
        exchange: String,
        /// Error original de `lapin`.
        #[source]
        source: lapin::Error,
    },
    /// El Broker respondió `nack` para el mensaje publicado: no se
    /// considera encolado.
    #[error("el Broker no confirmó la recepción del mensaje en el exchange '{exchange}'")]
    NotAcknowledged {
        /// Exchange contra el que se publicó el mensaje rechazado.
        exchange: String,
    },
    /// No se pudo serializar el `ScanRequest` a JSON antes de publicarlo.
    #[error("no se pudo serializar la solicitud de escaneo")]
    SerializationFailed(#[source] serde_json::Error),
    /// No se pudo iniciar el consumo de la cola indicada.
    #[error("no se pudo iniciar el consumo de la cola '{queue}'")]
    ConsumeFailed {
        /// Cola contra la que se intentó `basic_consume`.
        queue: &'static str,
        /// Error original de `lapin`.
        #[source]
        source: lapin::Error,
    },
}

/// Conecta contra `amqps_url` y `vhost`, confiando en `tls_config` para
/// verificar el certificado TLS del Broker, y crea un canal nuevo sobre esa
/// conexión — lógica de conexión compartida entre [`BrokerPublisher`] y
/// [`BrokerConsumer`] (la única diferencia entre publicar y consumir es que
/// el publicador además activa `confirm_select`, ver
/// [`BrokerPublisher::connect_with_tls_config`]).
async fn connect_channel(
    amqps_url: &SecretString,
    vhost: &str,
    tls_config: OwnedTLSConfig,
) -> Result<(Connection, Channel), BrokerError> {
    let uri = build_amqps_uri(amqps_url.expose_secret(), vhost);
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);

    let connection = Connection::connect_with_config(&uri, options, tls_config)
        .await
        .map_err(BrokerError::ConnectionFailed)?;
    let channel = connection
        .create_channel()
        .await
        .map_err(BrokerError::ConnectionFailed)?;

    Ok((connection, channel))
}

/// Abstracción sobre "publicar un [`ScanRequest`] en el Broker".
///
/// Permite que `AppState` (ver [`crate::api`]) guarde un
/// `Arc<dyn ScanRequestPublisher>` en vez de acoplarse a la implementación
/// concreta [`BrokerPublisher`] (conexión AMQPS real vía `lapin`): los
/// tests de otras features que construyen un `AppState` completo pero nunca
/// ejercen `POST /api/scans` pueden inyectar un doble de prueba en vez de
/// levantar un Broker real, igual que ya se hace con `usuarios_client`/
/// `oidc_client` para otras dependencias externas.
#[async_trait::async_trait]
pub trait ScanRequestPublisher: Send + Sync {
    /// Publica `request` en [`EXCHANGE_SCAN_REQUESTS`] (routing key
    /// [`ROUTING_KEY_SCAN_REQUEST`]), devolviendo éxito solo una vez que el
    /// Broker confirmó (`ack`) su recepción.
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError>;

    /// Publica `cancellation` en [`EXCHANGE_SCAN_CANCELLATIONS`] (routing key
    /// [`ROUTING_KEY_SCAN_CANCELLATION`]), devolviendo éxito solo una vez que
    /// el Broker confirmó (`ack`) su recepción (feature
    /// `scan_history_and_cancellation`).
    async fn publish_scan_cancellation(
        &self,
        cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError>;
}

/// Cliente `lapin` sobre AMQPS de este Gateway: conexión y canal
/// persistentes (una sola vez, reutilizados entre requests — ver
/// `progress/explore_lapin_publish.md` §5), con `confirm_select` ya
/// activado.
pub struct BrokerPublisher {
    // Se conserva únicamente para mantener viva la conexión mientras exista
    // el canal (`lapin::Channel` deja de funcionar si su `Connection` se
    // destruye) — ver `is_connected`, que sí la lee.
    connection: Connection,
    channel: Channel,
}

impl BrokerPublisher {
    /// Conecta contra `amqps_url` (incluye la credencial del usuario
    /// RabbitMQ `gateway`) y `vhost`, usando el almacén de certificados
    /// nativo del proceso para verificar TLS (adecuado para un Broker con
    /// certificado firmado por una CA pública/estándar).
    ///
    /// Falla con [`BrokerError::ConnectionFailed`] si la conexión, la
    /// creación del canal, o la activación de `confirm_select` no se
    /// pudieron completar.
    pub async fn connect(amqps_url: &SecretString, vhost: &str) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(amqps_url, vhost, OwnedTLSConfig::default()).await
    }

    /// Igual que [`Self::connect`], pero confiando además en la CA
    /// (`ca_pem`, en formato PEM) indicada — necesario para un Broker con
    /// certificado de una CA de laboratorio, no reconocida por el almacén
    /// nativo del proceso (p. ej. los tests de integración de esta feature,
    /// ver `progress/explore_lapin_testcontainers.md` §4).
    pub async fn connect_with_ca_pem(
        amqps_url: &SecretString,
        vhost: &str,
        ca_pem: String,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(
            amqps_url,
            vhost,
            OwnedTLSConfig {
                identity: None,
                cert_chain: Some(ca_pem),
            },
        )
        .await
    }

    async fn connect_with_tls_config(
        amqps_url: &SecretString,
        vhost: &str,
        tls_config: OwnedTLSConfig,
    ) -> Result<Self, BrokerError> {
        let (connection, channel) = connect_channel(amqps_url, vhost, tls_config).await?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(BrokerError::ConnectionFailed)?;

        Ok(Self {
            connection,
            channel,
        })
    }

    /// `true` si la conexión AMQPS subyacente sigue activa.
    pub fn is_connected(&self) -> bool {
        self.connection.status().connected()
    }
}

impl BrokerPublisher {
    /// Serializa `message` a JSON y lo publica en `exchange` (routing key
    /// `routing_key`), esperando el ack/nack real del Broker antes de
    /// devolver éxito (ver la nota de diseño "Confirms del Broker" al inicio
    /// de este módulo) — lógica compartida entre
    /// [`ScanRequestPublisher::publish_scan_request`] y
    /// [`ScanRequestPublisher::publish_scan_cancellation`], que solo difieren
    /// en el tipo de mensaje y el exchange/routing key de destino.
    async fn publish_and_confirm(
        &self,
        exchange: &'static str,
        routing_key: &'static str,
        message: &impl Serialize,
    ) -> Result<(), BrokerError> {
        let payload = serde_json::to_vec(message).map_err(BrokerError::SerializationFailed)?;

        let publisher_confirm = self
            .channel
            .basic_publish(
                exchange,
                routing_key,
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
            .map_err(|source| BrokerError::PublishFailed {
                exchange: exchange.to_string(),
                source,
            })?;

        let confirmation =
            publisher_confirm
                .await
                .map_err(|source| BrokerError::PublishFailed {
                    exchange: exchange.to_string(),
                    source,
                })?;

        if !confirmation.is_ack() {
            return Err(BrokerError::NotAcknowledged {
                exchange: exchange.to_string(),
            });
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ScanRequestPublisher for BrokerPublisher {
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError> {
        self.publish_and_confirm(EXCHANGE_SCAN_REQUESTS, ROUTING_KEY_SCAN_REQUEST, request)
            .await
    }

    async fn publish_scan_cancellation(
        &self,
        cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        self.publish_and_confirm(
            EXCHANGE_SCAN_CANCELLATIONS,
            ROUTING_KEY_SCAN_CANCELLATION,
            cancellation,
        )
        .await
    }
}

/// Callback invocado por [`BrokerConsumer::run`] por cada [`ScanOutcomeEvent`]
/// decodificado con éxito desde [`QUEUE_GATEWAY_SCAN_OUTCOMES`].
///
/// El mensaje ya se confirmó (`ack`) al Broker antes de invocar
/// [`Self::handle`] (ver [`BrokerConsumer::run`]): esta llamada es
/// best-effort respecto a sus propios efectos (actualizar `ms-usuarios`,
/// relayar por SSE) — un fallo interno debe loggearse dentro de la
/// implementación, nunca hacer panic ni propagarse, porque ya no hay nada
/// que "reintentar" a nivel de mensaje AMQP.
#[async_trait::async_trait]
pub trait ScanOutcomeHandler: Send + Sync {
    /// Procesa `event`.
    async fn handle(&self, event: ScanOutcomeEvent);
}

/// Cliente `lapin` sobre AMQPS de este Gateway: conexión y canal
/// persistentes dedicados a consumir [`QUEUE_GATEWAY_SCAN_OUTCOMES`]. A
/// diferencia de [`BrokerPublisher`], su canal no activa `confirm_select`
/// (irrelevante para consumir).
pub struct BrokerConsumer {
    // Igual que en `BrokerPublisher`: se conserva únicamente para mantener
    // viva la conexión mientras exista el canal.
    connection: Connection,
    channel: Channel,
}

impl BrokerConsumer {
    /// Conecta contra `amqps_url` (incluye la credencial del usuario
    /// RabbitMQ `gateway`) y `vhost`, usando el almacén de certificados
    /// nativo del proceso para verificar TLS (adecuado para un Broker con
    /// certificado firmado por una CA pública/estándar).
    pub async fn connect(amqps_url: &SecretString, vhost: &str) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(amqps_url, vhost, OwnedTLSConfig::default()).await
    }

    /// Igual que [`Self::connect`], pero confiando además en la CA
    /// (`ca_pem`, en formato PEM) indicada — necesario para un Broker con
    /// certificado de una CA de laboratorio (tests de integración de esta
    /// feature).
    pub async fn connect_with_ca_pem(
        amqps_url: &SecretString,
        vhost: &str,
        ca_pem: String,
    ) -> Result<Self, BrokerError> {
        Self::connect_with_tls_config(
            amqps_url,
            vhost,
            OwnedTLSConfig {
                identity: None,
                cert_chain: Some(ca_pem),
            },
        )
        .await
    }

    async fn connect_with_tls_config(
        amqps_url: &SecretString,
        vhost: &str,
        tls_config: OwnedTLSConfig,
    ) -> Result<Self, BrokerError> {
        let (connection, channel) = connect_channel(amqps_url, vhost, tls_config).await?;
        Ok(Self {
            connection,
            channel,
        })
    }

    /// `true` si la conexión AMQPS subyacente sigue activa.
    pub fn is_connected(&self) -> bool {
        self.connection.status().connected()
    }

    /// Consume [`QUEUE_GATEWAY_SCAN_OUTCOMES`] indefinidamente, decodificando
    /// cada mensaje contra [`ScanOutcomeEvent`] (que refleja literalmente
    /// `broker/contracts/scan-outcome.schema.json`).
    ///
    /// - Un mensaje que decodifica con éxito se confirma (`ack`) y se pasa a
    ///   `handler.handle` (best-effort, ver [`ScanOutcomeHandler`]).
    /// - Un mensaje que **no** decodifica (malformado) se descarta con
    ///   `nack(requeue: false)` (dead-letter inmediato hacia
    ///   `gateway.scan-outcomes.dlq`, ya aprovisionada por
    ///   `broker/rabbitmq/definitions.json`) y se loggea sin incluir el
    ///   payload completo (solo el motivo de deserialización, la
    ///   `routing_key`, y el tamaño en bytes — nunca contenido potencialmente
    ///   sensible del mensaje, ver `docs/security-scope.md`). Nunca tumba
    ///   este bucle.
    /// - Esta función **no reconecta** si el `Stream` del consumidor
    ///   termina (canal/conexión cerrados): loggea el fin y retorna (ver la
    ///   nota de diseño al inicio de este módulo). Pensada para lanzarse una
    ///   única vez con `tokio::spawn` al arrancar el proceso (ver
    ///   `crate::wiring`).
    pub async fn run(self, handler: Arc<dyn ScanOutcomeHandler>) {
        let mut consumer = match self
            .channel
            .basic_consume(
                QUEUE_GATEWAY_SCAN_OUTCOMES,
                CONSUMER_TAG,
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
        {
            Ok(consumer) => consumer,
            Err(source) => {
                tracing::error!(
                    error = %BrokerError::ConsumeFailed { queue: QUEUE_GATEWAY_SCAN_OUTCOMES, source },
                    "no se pudo iniciar el consumo de gateway.scan-outcomes"
                );
                return;
            }
        };

        while let Some(delivery) = consumer.next().await {
            let delivery = match delivery {
                Ok(delivery) => delivery,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "error de transporte consumiendo gateway.scan-outcomes"
                    );
                    continue;
                }
            };

            match serde_json::from_slice::<ScanOutcomeEvent>(&delivery.data) {
                Ok(event) => {
                    if let Err(err) = delivery.ack(BasicAckOptions::default()).await {
                        tracing::error!(
                            error = %err,
                            "no se pudo confirmar (ack) un ScanOutcome consumido"
                        );
                    }
                    handler.handle(event).await;
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        routing_key = %delivery.routing_key.as_str(),
                        payload_len = delivery.data.len(),
                        "mensaje malformado en gateway.scan-outcomes descartado"
                    );
                    if let Err(nack_err) = delivery
                        .nack(BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        })
                        .await
                    {
                        tracing::error!(
                            error = %nack_err,
                            "no se pudo descartar (nack) un mensaje malformado de gateway.scan-outcomes"
                        );
                    }
                }
            }
        }

        tracing::error!(
            "el consumidor de gateway.scan-outcomes terminó (stream agotado, canal/conexión \
             cerrados); no se reconecta automáticamente (ver la nota de diseño al inicio de \
             este módulo)"
        );
    }
}

/// Construye la URI AMQPS completa (`<base>/<vhost>`) que espera
/// `lapin::Connection::connect*`, dado que este servicio guarda la URL base
/// (credencial + host + puerto) y el vhost en campos separados de
/// [`crate::config::Config`].
fn build_amqps_uri(base_url: &str, vhost: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), vhost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_amqps_uri_appends_vhost() {
        assert_eq!(
            build_amqps_uri("amqps://gateway:secret@broker.lab:5671", "security-app"),
            "amqps://gateway:secret@broker.lab:5671/security-app"
        );
    }

    #[test]
    fn build_amqps_uri_tolerates_trailing_slash_in_base_url() {
        assert_eq!(
            build_amqps_uri("amqps://gateway:secret@broker.lab:5671/", "security-app"),
            "amqps://gateway:secret@broker.lab:5671/security-app"
        );
    }

    #[test]
    fn scan_request_debug_redacts_ssh_credentials_ref() {
        let request = ScanRequest {
            correlation_id: "corr-1".to_string(),
            ip: "192.0.2.10".to_string(),
            network_user: "netuser".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
            requested_by: "google-sub-123".to_string(),
        };

        let debug_output = format!("{request:?}");

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("corr-1"));
    }

    #[test]
    fn scan_request_serializes_with_the_exact_contract_fields() {
        let request = ScanRequest {
            correlation_id: "corr-1".to_string(),
            ip: "192.0.2.10".to_string(),
            network_user: "netuser".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
            requested_by: "google-sub-123".to_string(),
        };

        let value = serde_json::to_value(&request).expect("debe serializar a JSON");
        let object = value.as_object().expect("debe ser un objeto JSON");

        let expected_keys = [
            "correlation_id",
            "ip",
            "network_user",
            "ssh_credentials_ref",
            "has_sudo",
            "requested_by",
        ];
        assert_eq!(object.len(), expected_keys.len());
        for key in expected_keys {
            assert!(object.contains_key(key), "falta la clave '{key}'");
        }
    }

    #[test]
    fn scan_cancellation_serializes_with_exactly_the_contract_fields() {
        let cancellation = ScanCancellation {
            correlation_id: "scan-1".to_string(),
            requested_by: "google-sub-123".to_string(),
        };

        let value = serde_json::to_value(&cancellation).expect("debe serializar a JSON");
        let object = value.as_object().expect("debe ser un objeto JSON");

        let expected_keys = ["correlation_id", "requested_by"];
        assert_eq!(
            object.len(),
            expected_keys.len(),
            "el ScanCancellation publicado no debe traer campos extra (additionalProperties: false)"
        );
        for key in expected_keys {
            assert!(object.contains_key(key), "falta la clave '{key}'");
        }
        assert_eq!(object["correlation_id"], serde_json::json!("scan-1"));
        assert_eq!(object["requested_by"], serde_json::json!("google-sub-123"));
    }
}
