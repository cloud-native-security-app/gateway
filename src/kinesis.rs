//! Adaptador Kinesis del puerto [`SecurityEventPublisher`] (feature
//! `security_event_publisher`, tarea KAP-06).
//!
//! Publica cada [`SecurityEvent`] como un registro JSON (el cuerpo del
//! contrato `security-event.schema.json`) en el Kinesis Data Stream
//! `security-events`, con [`SecurityEvent::partition_key`] como clave de
//! partición. Las credenciales salen de la cadena de proveedores por defecto
//! de AWS (rol de la tarea ECS); nunca hay claves estáticas en código.
//! `AWS_ENDPOINT_URL` solo se usa contra LocalStack, igual que en
//! [`crate::sns`].
//!
//! Un registro de Kinesis admite hasta 1 MiB; un evento de este contrato pesa
//! cientos de bytes, así que no hay guarda de tamaño. El cuerpo del evento
//! nunca se loggea ni se incluye en un error.

use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::Client;

use crate::security_events::{SecurityEvent, SecurityEventError, SecurityEventPublisher};

/// Publicador de eventos de seguridad sobre un Kinesis Data Stream.
#[derive(Debug, Clone)]
pub struct KinesisSecurityEventPublisher {
    client: Client,
    stream_name: String,
}

impl KinesisSecurityEventPublisher {
    /// Construye el publicador sobre un `client` ya configurado (los tests
    /// inyectan uno apuntando a LocalStack).
    pub fn from_client(client: Client, stream_name: String) -> Self {
        Self {
            client,
            stream_name,
        }
    }

    /// Construye el publicador con la cadena de credenciales por defecto de
    /// AWS, la `region` indicada y, opcionalmente, un `endpoint_url` (solo
    /// LocalStack).
    pub async fn connect(region: &str, endpoint_url: Option<&str>, stream_name: String) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(url) = endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let shared = loader.load().await;
        Self::from_client(Client::new(&shared), stream_name)
    }
}

#[async_trait::async_trait]
impl SecurityEventPublisher for KinesisSecurityEventPublisher {
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError> {
        let body = serde_json::to_vec(event).map_err(SecurityEventError::SerializationFailed)?;
        self.client
            .put_record()
            .stream_name(&self.stream_name)
            .partition_key(event.partition_key())
            .data(Blob::new(body))
            .send()
            .await
            .map_err(|source| SecurityEventError::PublishFailed(Box::new(source)))?;
        Ok(())
    }
}
