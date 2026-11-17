//! Puertos de mensajería de este Gateway y sus tipos de mensaje: publicación
//! de `ScanRequest`/`ScanCancellation` ([`ScanRequestPublisher`]) y callback de
//! consumo de resultados de escaneo ([`ScanOutcomeHandler`]).
//!
//! La mensajería real vive en los adaptadores AWS: [`crate::sns`] implementa
//! [`ScanRequestPublisher`] sobre topics SNS y [`crate::sqs`] consume la cola
//! SQS de resultados invocando un [`ScanOutcomeHandler`]. (Antes este módulo
//! contenía el cliente AMQP `lapin` contra RabbitMQ; ver `docs/decisions.md`,
//! D-15, que lo reemplaza.) Los cuerpos JSON son los mismos contratos de
//! `broker/contracts/*.schema.json`; la antigua routing key viaja ahora como
//! atributo de mensaje `routing_key`.
//!
//! ## Decisiones de diseño
//!
//! - **Un solo trait para publicar**: [`ScanRequestPublisher`] cubre tanto
//!   `ScanRequest` como `ScanCancellation` para no introducir un segundo campo
//!   en `AppState` ni otro doble de prueba por cada test que construye un
//!   `AppState` completo.
//! - **No se declara topología**: este Gateway no crea topics, colas ni
//!   suscripciones (lo hace `broker`/Terraform); solo publica y consume con
//!   los permisos del rol de la tarea (ver `docs/security-scope.md`).
//! - **Nunca se loggean cuerpos**: un [`ScanRequest`] transporta
//!   `ssh_credentials_ref`; ningún error de [`BrokerError`] incluye el cuerpo.
//! - **Entrega al menos una vez**: SQS puede entregar duplicados; el
//!   [`ScanOutcomeHandler`] debe ser idempotente (ver [`crate::sqs`]).

use serde::Serialize;

use crate::domain::{ScanMode, ScanOutcomeEvent};

/// Routing key (atributo de mensaje `routing_key`) con la que este Gateway
/// publica cada `ScanRequest`.
pub const ROUTING_KEY_SCAN_REQUEST: &str = "scan.request";

/// Routing key (atributo de mensaje `routing_key`) con la que este Gateway
/// publica cada `ScanCancellation`.
pub const ROUTING_KEY_SCAN_CANCELLATION: &str = "scan.cancellation";

/// Mensaje publicado en el topic SNS de solicitudes (routing key
/// [`ROUTING_KEY_SCAN_REQUEST`]), consumido por `ms-nmap`. Shape copiado
/// literalmente de `broker/contracts/scan-request.schema.json`
/// (`additionalProperties: false`): `correlation_id`, `ip` y `requested_by`
/// siempre; `scan_mode` solo en modo `network` (ausente == `ssh`, así el
/// payload ssh es idéntico al previo al campo); `network_user`,
/// `ssh_credentials_ref` y `has_sudo` solo en modo `ssh` y **nunca** en
/// `network` (el schema los prohíbe: una credencial no viaja con un escaneo de
/// red). Constrúyelo con [`ScanRequest::ssh`] o [`ScanRequest::network`].
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
    /// Modo del escaneo; se serializa solo si no es [`ScanMode::Ssh`].
    #[serde(skip_serializing_if = "ScanMode::is_ssh")]
    pub scan_mode: ScanMode,
    /// Dirección IP única objetivo del escaneo, ya normalizada por
    /// [`crate::domain::ScanSubmission`] (siempre parseable como `IpAddr`,
    /// nunca un CIDR).
    pub ip: String,
    /// Nombre de host tal como lo escribió el usuario, en minúsculas (solo
    /// modo `network` con un nombre o URL; feature `network_scan_url_target`).
    /// Sirve para mostrar y como host HTTP virtual: `ip` sigue siendo la
    /// dirección fijada que se escanea.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    /// Puerto de la URL que se escanea además de los de nmap por defecto
    /// (solo modo `network`; ver [`crate::network_target::NetworkTarget`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_port: Option<u16>,
    /// Usuario de red resuelto por `ms-usuarios` para este objetivo (solo
    /// modo `ssh`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_user: Option<String>,
    /// Credencial SSH real resuelta por `ms-usuarios` para este objetivo
    /// (solo modo `ssh`). Nunca se loggea (ver `docs/security-scope.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_credentials_ref: Option<String>,
    /// Si el usuario de red resuelto tiene privilegios `sudo` en el
    /// objetivo (solo modo `ssh`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_sudo: Option<bool>,
    /// Identidad (ya verificada por este Gateway) de quien solicitó el
    /// escaneo.
    pub requested_by: String,
}

impl ScanRequest {
    /// Solicitud en modo `ssh`: lleva las tres credenciales resueltas.
    pub fn ssh(
        correlation_id: String,
        ip: String,
        network_user: String,
        ssh_credentials_ref: String,
        has_sudo: bool,
        requested_by: String,
    ) -> Self {
        Self {
            correlation_id,
            scan_mode: ScanMode::Ssh,
            ip,
            target_host: None,
            extra_port: None,
            network_user: Some(network_user),
            ssh_credentials_ref: Some(ssh_credentials_ref),
            has_sudo: Some(has_sudo),
            requested_by,
        }
    }

    /// Solicitud en modo `network`: sin ningún campo de credenciales SSH.
    pub fn network(correlation_id: String, ip: String, requested_by: String) -> Self {
        Self {
            correlation_id,
            scan_mode: ScanMode::Network,
            ip,
            target_host: None,
            extra_port: None,
            network_user: None,
            ssh_credentials_ref: None,
            has_sudo: None,
            requested_by,
        }
    }

    /// Añade el nombre de host y el puerto extra de un objetivo `network`
    /// dado por nombre o URL.
    pub fn with_network_target(
        mut self,
        target_host: Option<String>,
        extra_port: Option<u16>,
    ) -> Self {
        self.target_host = target_host;
        self.extra_port = extra_port;
        self
    }
}

impl std::fmt::Debug for ScanRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanRequest")
            .field("correlation_id", &self.correlation_id)
            .field("scan_mode", &self.scan_mode)
            .field("ip", &self.ip)
            .field("target_host", &self.target_host)
            .field("extra_port", &self.extra_port)
            .field("network_user", &self.network_user)
            .field(
                "ssh_credentials_ref",
                &self.ssh_credentials_ref.as_ref().map(|_| "[REDACTED]"),
            )
            .field("has_sudo", &self.has_sudo)
            .field("requested_by", &self.requested_by)
            .finish()
    }
}

/// Mensaje publicado en el topic SNS de cancelaciones (routing key
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

/// Errores al comunicarse con el Broker (SNS/SQS) desde este Gateway
/// (publicar o consumir).
///
/// Ninguna variante incluye el cuerpo de un mensaje (un `ScanRequest`
/// transporta `ssh_credentials_ref`, ver `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// No se pudo publicar en el topic SNS indicado (adaptador
    /// [`crate::sns::SnsScanPublisher`]). La causa original del SDK se
    /// conserva en `source` (solo visible vía `Debug`/cadena de `source()`,
    /// nunca en el `Display`); jamás incluye el cuerpo del mensaje.
    #[error("no se pudo publicar en el topic SNS '{topic}'")]
    SnsPublishFailed {
        /// ARN del topic contra el que se intentó publicar.
        topic: String,
        /// Error original del SDK de AWS, borrado a un trait object para no
        /// acoplar esta API pública al tipo genérico del SDK.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Falló una operación contra una cola SQS (enviar a la DLQ o borrar un
    /// mensaje; adaptador [`crate::sqs::SqsScanOutcomeConsumer`]). La causa
    /// del SDK se conserva en `source`; jamás incluye el cuerpo del mensaje.
    #[error("falló una operación contra la cola SQS '{queue}'")]
    SqsFailed {
        /// URL de la cola contra la que se intentó la operación.
        queue: String,
        /// Error original del SDK de AWS, borrado a un trait object.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// No se pudo serializar el mensaje a JSON antes de publicarlo.
    #[error("no se pudo serializar la solicitud de escaneo")]
    SerializationFailed(#[source] serde_json::Error),
}

/// Abstracción sobre "publicar un [`ScanRequest`]/[`ScanCancellation`] en el
/// Broker".
///
/// Permite que `AppState` (ver [`crate::api`]) guarde un
/// `Arc<dyn ScanRequestPublisher>` en vez de acoplarse a la implementación
/// concreta [`crate::sns::SnsScanPublisher`]: los tests de otras features
/// que construyen un `AppState` completo pero nunca ejercen
/// `POST /api/scans` pueden inyectar un doble de prueba en vez de levantar
/// LocalStack, igual que ya se hace con `usuarios_client`/`oidc_client` para
/// otras dependencias externas.
#[async_trait::async_trait]
pub trait ScanRequestPublisher: Send + Sync {
    /// Publica `request` en el topic de solicitudes (routing key
    /// [`ROUTING_KEY_SCAN_REQUEST`]), devolviendo éxito solo una vez que SNS
    /// aceptó el mensaje.
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError>;

    /// Publica `cancellation` en el topic de cancelaciones (routing key
    /// [`ROUTING_KEY_SCAN_CANCELLATION`]), devolviendo éxito solo una vez que
    /// SNS aceptó el mensaje (feature `scan_history_and_cancellation`).
    async fn publish_scan_cancellation(
        &self,
        cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError>;
}

/// Callback invocado por [`crate::sqs::SqsScanOutcomeConsumer::run`] por cada
/// [`ScanOutcomeEvent`] decodificado con éxito desde la cola de resultados.
///
/// El mensaje se borra de SQS **después** de que [`Self::handle`] retorna: si
/// el proceso muere a mitad, SQS lo reentrega, así que la implementación debe
/// tolerar duplicados. Un fallo interno (actualizar `ms-usuarios`, relayar por
/// SSE) debe loggearse dentro de la implementación, nunca hacer panic ni
/// propagarse.
#[async_trait::async_trait]
pub trait ScanOutcomeHandler: Send + Sync {
    /// Procesa `event`.
    async fn handle(&self, event: ScanOutcomeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_scan_request_payload_is_byte_identical_to_the_pre_scan_mode_contract() {
        let request = ScanRequest::ssh(
            "corr-1".to_string(),
            "192.0.2.10".to_string(),
            "netuser".to_string(),
            "lab-only-not-a-real-secret".to_string(),
            true,
            "google-sub-123".to_string(),
        );

        assert_eq!(
            serde_json::to_string(&request).expect("serializa"),
            r#"{"correlation_id":"corr-1","ip":"192.0.2.10","network_user":"netuser","ssh_credentials_ref":"lab-only-not-a-real-secret","has_sudo":true,"requested_by":"google-sub-123"}"#
        );
    }

    #[test]
    fn network_scan_request_carries_the_mode_and_no_ssh_fields() {
        let request = ScanRequest::network(
            "corr-2".to_string(),
            "192.0.2.10".to_string(),
            "google-sub-123".to_string(),
        );

        assert_eq!(
            serde_json::to_value(&request).expect("serializa"),
            serde_json::json!({
                "correlation_id": "corr-2",
                "scan_mode": "network",
                "ip": "192.0.2.10",
                "requested_by": "google-sub-123",
            })
        );
        assert_eq!(request.scan_mode, crate::domain::ScanMode::Network);
    }

    #[test]
    fn network_scan_request_carries_target_host_and_extra_port_only_when_set() {
        let request = ScanRequest::network(
            "corr-3".to_string(),
            "192.0.2.10".to_string(),
            "google-sub-123".to_string(),
        )
        .with_network_target(Some("app.example.com".to_string()), Some(8443));

        assert_eq!(
            serde_json::to_value(&request).expect("serializa"),
            serde_json::json!({
                "correlation_id": "corr-3",
                "scan_mode": "network",
                "ip": "192.0.2.10",
                "target_host": "app.example.com",
                "extra_port": 8443,
                "requested_by": "google-sub-123",
            })
        );
    }

    #[test]
    fn scan_request_debug_redacts_ssh_credentials_ref() {
        let request = ScanRequest::ssh(
            "corr-1".to_string(),
            "192.0.2.10".to_string(),
            "netuser".to_string(),
            "lab-only-not-a-real-secret".to_string(),
            true,
            "google-sub-123".to_string(),
        );

        let debug_output = format!("{request:?}");

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("corr-1"));
    }

    #[test]
    fn scan_request_serializes_with_the_exact_contract_fields() {
        let request = ScanRequest::ssh(
            "corr-1".to_string(),
            "192.0.2.10".to_string(),
            "netuser".to_string(),
            "lab-only-not-a-real-secret".to_string(),
            true,
            "google-sub-123".to_string(),
        );

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

    #[test]
    fn sns_publish_failed_display_names_the_topic_and_keeps_the_source_chain() {
        use std::error::Error as _;
        let err = BrokerError::SnsPublishFailed {
            topic: "arn:aws:sns:us-east-1:000000000000:scan-requests".to_string(),
            source: "boom".into(),
        };
        assert_eq!(
            err.to_string(),
            "no se pudo publicar en el topic SNS 'arn:aws:sns:us-east-1:000000000000:scan-requests'"
        );
        assert_eq!(
            err.source().expect("debe encadenar la causa").to_string(),
            "boom"
        );
    }
}
