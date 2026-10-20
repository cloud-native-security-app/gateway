//! Adaptador SNS del puerto [`ScanRequestPublisher`] (tarea MSG-GW-02).
//!
//! Publica los cuerpos JSON del contrato (`serde_json::to_string` de
//! [`ScanRequest`]/[`ScanCancellation`]) en dos topics SNS, y transporta la
//! routing key (herencia del antiguo Broker AMQP) como atributo de
//! mensaje `String` llamado `routing_key`, para que las colas SQS suscritas
//! (con `RawMessageDelivery=true`) puedan filtrar por él.
//!
//! Las credenciales salen de la cadena de proveedores por defecto de AWS
//! (rol de la tarea ECS); nunca hay claves estáticas en código.
//!
//! SNS limita el mensaje a 256 KB; los cuerpos de este contrato son de
//! cientos de bytes, así que no hay guarda de tamaño. Los cuerpos nunca se
//! loggean: un `ScanRequest` transporta `ssh_credentials_ref`.

use aws_sdk_sns::types::MessageAttributeValue;
use aws_sdk_sns::Client;
use serde::Serialize;

use crate::broker::{
    BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher,
    ROUTING_KEY_SCAN_CANCELLATION, ROUTING_KEY_SCAN_REQUEST,
};

/// Nombre del atributo de mensaje SNS que transporta la routing key.
pub const ROUTING_KEY_ATTRIBUTE: &str = "routing_key";

/// Publicador de solicitudes y cancelaciones de escaneo sobre SNS.
#[derive(Debug, Clone)]
pub struct SnsScanPublisher {
    client: Client,
    requests_topic_arn: String,
    cancellations_topic_arn: String,
}

impl SnsScanPublisher {
    /// Construye el publicador sobre un `client` ya configurado (los tests
    /// inyectan uno apuntando a LocalStack).
    pub fn from_client(
        client: Client,
        requests_topic_arn: String,
        cancellations_topic_arn: String,
    ) -> Self {
        Self {
            client,
            requests_topic_arn,
            cancellations_topic_arn,
        }
    }

    /// Construye el publicador con la cadena de credenciales por defecto de
    /// AWS, la `region` indicada y, opcionalmente, un `endpoint_url`
    /// (solo LocalStack).
    pub async fn connect(
        region: &str,
        endpoint_url: Option<&str>,
        requests_topic_arn: String,
        cancellations_topic_arn: String,
    ) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(url) = endpoint_url {
            loader = loader.endpoint_url(url);
        }
        let shared = loader.load().await;
        Self::from_client(
            Client::new(&shared),
            requests_topic_arn,
            cancellations_topic_arn,
        )
    }

    async fn publish<T: Serialize>(
        &self,
        topic_arn: &str,
        routing_key: &str,
        message: &T,
    ) -> Result<(), BrokerError> {
        let body = serde_json::to_string(message).map_err(BrokerError::SerializationFailed)?;
        self.client
            .publish()
            .topic_arn(topic_arn)
            .message(body)
            .message_attributes(ROUTING_KEY_ATTRIBUTE, routing_key_attribute(routing_key))
            .send()
            .await
            .map_err(|source| BrokerError::SnsPublishFailed {
                topic: topic_arn.to_string(),
                source: Box::new(source),
            })?;
        Ok(())
    }
}

/// Atributo `String` de SNS con la routing key `value`.
fn routing_key_attribute(value: &str) -> MessageAttributeValue {
    MessageAttributeValue::builder()
        .data_type("String")
        .string_value(value)
        .build()
        .expect("data_type está presente")
}

#[async_trait::async_trait]
impl ScanRequestPublisher for SnsScanPublisher {
    async fn publish_scan_request(&self, request: &ScanRequest) -> Result<(), BrokerError> {
        self.publish(&self.requests_topic_arn, ROUTING_KEY_SCAN_REQUEST, request)
            .await
    }

    async fn publish_scan_cancellation(
        &self,
        cancellation: &ScanCancellation,
    ) -> Result<(), BrokerError> {
        self.publish(
            &self.cancellations_topic_arn,
            ROUTING_KEY_SCAN_CANCELLATION,
            cancellation,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_key_attribute_is_a_string_attribute() {
        let attr = routing_key_attribute("scan.request");
        assert_eq!(attr.data_type(), "String");
        assert_eq!(attr.string_value(), Some("scan.request"));
    }
}
