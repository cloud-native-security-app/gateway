//! Cliente `lapin` sobre AMQPS: publicación de `ScanRequest`/
//! `ScanCancellation` y consumo de `gateway.scan-outcomes`.
//!
//! Esta feature (`scan_submission`) implementa únicamente
//! [`publish_scan_request`](BrokerPublisher::publish_scan_request); el
//! consumidor de `gateway.scan-outcomes` es responsabilidad de la feature
//! `scan_outcome_relay`, fuera de alcance aquí.
//!
//! ## Decisiones de diseño
//!
//! - **`lapin` 2.5.5, no 4.x**: `Cargo.lock` de este repo fija `lapin`
//!   2.5.5, con una API de conexión distinta a la que documenta el repo
//!   hermano `broker/` (que usa `lapin` 4.x). Ver
//!   `progress/explore_lapin_publish.md` para el detalle verificado contra
//!   el código fuente real de esta versión.
//! - **No se declara topología**: el usuario RabbitMQ `gateway` (definido en
//!   `broker/rabbitmq/definitions.json`) solo tiene permiso `write` sobre
//!   `scan.requests`/`scan.cancellations` (`configure: "^$"`) — este módulo
//!   solo llama a `basic_publish`, nunca a `exchange_declare`/
//!   `queue_declare` (ver `docs/architecture.md` §"Qué NO hacer").
//! - **Confirms del Broker**: el canal activa `confirm_select` una sola vez
//!   al conectar, y [`BrokerPublisher::publish_scan_request`] espera el
//!   ack/nack real (no solo el envío del frame) antes de devolver éxito.
//!   Trade-off documentado: RNF-04 exige que `POST /api/scans` responda en
//!   <500ms, no "instantáneamente"; un ack de RabbitMQ en la misma subred
//!   privada añade típicamente un solo dígito de milisegundos, muy por
//!   debajo de ese presupuesto, y es lo único que permite distinguir "el
//!   frame se envió" de "el Broker aceptó el mensaje" — distinción que
//!   necesita el criterio de aceptación de `scan_submission` sobre marcar
//!   `Fallido` un histórico cuyo `ScanRequest` no llegó a publicarse. Ver
//!   `progress/explore_lapin_publish.md` §4 para el análisis completo.
//! - **Sin reconexión automática**: `lapin` 2.5.5 no reconecta solo (ver
//!   `progress/explore_lapin_publish.md` §3.3). Esta feature no implementa
//!   lógica de reconexión (fuera del alcance de `scan_submission`, que solo
//!   exige detectar y reportar un fallo de publicación, no recuperarse de
//!   él): un canal/conexión muerta se reporta como [`BrokerError`] igual
//!   que cualquier otro fallo de publicación.

use lapin::options::{BasicPublishOptions, ConfirmSelectOptions};
use lapin::protocol::BasicProperties;
use lapin::tcp::OwnedTLSConfig;
use lapin::{Channel, Connection, ConnectionProperties};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

/// Exchange donde este Gateway publica cada `ScanRequest` (topic, ya
/// declarado por `broker/rabbitmq/definitions.json` — no se redeclara
/// aquí).
pub const EXCHANGE_SCAN_REQUESTS: &str = "scan.requests";

/// Routing key con la que este Gateway publica cada `ScanRequest`.
pub const ROUTING_KEY_SCAN_REQUEST: &str = "scan.request";

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

/// Errores al publicar en el Broker desde este Gateway.
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

#[async_trait::async_trait]
impl ScanRequestPublisher for BrokerPublisher {
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError> {
        let payload = serde_json::to_vec(request).map_err(BrokerError::SerializationFailed)?;

        let publisher_confirm = self
            .channel
            .basic_publish(
                EXCHANGE_SCAN_REQUESTS,
                ROUTING_KEY_SCAN_REQUEST,
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
            .map_err(|source| BrokerError::PublishFailed {
                exchange: EXCHANGE_SCAN_REQUESTS.to_string(),
                source,
            })?;

        let confirmation =
            publisher_confirm
                .await
                .map_err(|source| BrokerError::PublishFailed {
                    exchange: EXCHANGE_SCAN_REQUESTS.to_string(),
                    source,
                })?;

        if !confirmation.is_ack() {
            return Err(BrokerError::NotAcknowledged {
                exchange: EXCHANGE_SCAN_REQUESTS.to_string(),
            });
        }

        Ok(())
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
}
