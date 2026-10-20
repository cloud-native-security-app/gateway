//! Arnés compartido de los tests de integración que corren contra un
//! LocalStack real (SNS + SQS) levantado con `testcontainers` — sin mocks y
//! sin cuenta AWS. Cada test levanta su propio contenedor, así que los
//! nombres de topics/colas nunca colisionan entre tests.

// Cada binario de test (`tests/*.rs`) compila este módulo por separado y solo
// usa una parte de sus helpers.
#![allow(dead_code)]

use std::time::Duration;

use aws_sdk_sns::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_sqs::types::{Message, MessageAttributeValue, QueueAttributeName};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

pub const LOCALSTACK_TAG: &str = "4.4";
pub const REGION: &str = "us-east-1";

/// LocalStack en marcha más clientes SNS/SQS ya apuntados a él. El
/// contenedor se destruye al soltar este valor.
pub struct LocalStack {
    _container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub sns: aws_sdk_sns::Client,
    pub sqs: aws_sdk_sqs::Client,
}

impl LocalStack {
    pub async fn start() -> Self {
        let container = GenericImage::new("localstack/localstack", LOCALSTACK_TAG)
            .with_exposed_port(4566.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .start()
            .await
            .expect("el contenedor LocalStack de test debe arrancar");
        let port = container
            .get_host_port_ipv4(4566.tcp())
            .await
            .expect("LocalStack debe publicar el puerto 4566");
        let endpoint = format!("http://127.0.0.1:{port}");
        let credentials = || Credentials::new("test", "test", None, None, "localstack-test");
        let sns = aws_sdk_sns::Client::from_conf(
            aws_sdk_sns::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(credentials())
                .build(),
        );
        Self {
            _container: container,
            endpoint,
            sns,
            sqs,
        }
    }

    async fn queue_arn(&self, queue_url: &str) -> String {
        self.sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos")
            .remove(&QueueAttributeName::QueueArn)
            .expect("arn de la cola")
    }

    /// Crea un topic `name` y una cola `name` suscrita con
    /// `RawMessageDelivery=true` (lo que el gateway publica llega tal cual,
    /// con el atributo `routing_key`); devuelve `(topic_arn, queue_url)`.
    pub async fn topic_with_queue(&self, name: &str) -> (String, String) {
        let topic_arn = self
            .sns
            .create_topic()
            .name(name)
            .send()
            .await
            .expect("crear topic")
            .topic_arn
            .expect("topic arn");
        let queue_url = self
            .sqs
            .create_queue()
            .queue_name(name)
            .send()
            .await
            .expect("crear cola")
            .queue_url
            .expect("queue url");
        let queue_arn = self.queue_arn(&queue_url).await;
        self.sns
            .subscribe()
            .topic_arn(&topic_arn)
            .protocol("sqs")
            .endpoint(&queue_arn)
            .attributes("RawMessageDelivery", "true")
            .send()
            .await
            .expect("suscribir la cola al topic");
        (topic_arn, queue_url)
    }

    /// Crea la cola de resultados de escaneo con su DLQ (`RedrivePolicy`
    /// `maxReceiveCount: 3`, visibilidad corta); devuelve
    /// `(queue_url, dlq_url)`.
    pub async fn outcomes_queue_with_dlq(&self) -> (String, String) {
        let dlq_url = self
            .sqs
            .create_queue()
            .queue_name("gateway-scan-outcomes-dlq")
            .send()
            .await
            .expect("crear DLQ")
            .queue_url
            .expect("url DLQ");
        let dlq_arn = self.queue_arn(&dlq_url).await;
        let redrive = format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":3}}"#);
        let queue_url = self
            .sqs
            .create_queue()
            .queue_name("gateway-scan-outcomes")
            .attributes(QueueAttributeName::VisibilityTimeout, "2")
            .attributes(QueueAttributeName::RedrivePolicy, redrive)
            .send()
            .await
            .expect("crear cola de resultados")
            .queue_url
            .expect("url cola de resultados");
        (queue_url, dlq_url)
    }

    /// Encola `body` en `queue_url` como lo haría `ms-nmap` a través de SNS
    /// (con el atributo `routing_key`).
    pub async fn send_with_routing_key(&self, queue_url: &str, routing_key: &str, body: &str) {
        self.sqs
            .send_message()
            .queue_url(queue_url)
            .message_body(body)
            .message_attributes(
                "routing_key",
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(routing_key)
                    .build()
                    .expect("data_type presente"),
            )
            .send()
            .await
            .expect("enviar mensaje");
    }

    /// Recibe un mensaje de `queue_url` y lo borra (reintentos con long
    /// polling corto); `None` si no llega ninguno.
    pub async fn receive_one(&self, queue_url: &str) -> Option<Message> {
        for _ in 0..10 {
            let out = self
                .sqs
                .receive_message()
                .queue_url(queue_url)
                .message_attribute_names("All")
                .wait_time_seconds(2)
                .max_number_of_messages(1)
                .send()
                .await
                .expect("recibir de la cola");
            if let Some(message) = out.messages.and_then(|m| m.into_iter().next()) {
                if let Some(handle) = message.receipt_handle() {
                    let _ = self
                        .sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(handle)
                        .send()
                        .await;
                }
                return Some(message);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    }
}

/// Valor del atributo `routing_key` de `message`.
pub fn routing_key_of(message: &Message) -> String {
    message
        .message_attributes()
        .and_then(|attrs| attrs.get("routing_key"))
        .and_then(|value| value.string_value())
        .expect("el mensaje debe traer el atributo routing_key")
        .to_string()
}
