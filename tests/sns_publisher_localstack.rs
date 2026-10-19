//! Test de integración de `SnsScanPublisher` (tarea MSG-GW-02) contra un
//! LocalStack real levantado con `testcontainers` (sin mocks, sin cuenta
//! AWS): se crean dos topics SNS y una cola SQS suscrita a cada uno con
//! `RawMessageDelivery=true`, se publica con el adaptador y se verifica que
//! el cuerpo JSON y el atributo `routing_key` llegan a cada cola.

use std::time::Duration;

use aws_sdk_sns::config::{BehaviorVersion, Credentials, Region};
use serde_json::{json, Value};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

use gateway::broker::{
    BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher,
    ROUTING_KEY_SCAN_CANCELLATION, ROUTING_KEY_SCAN_REQUEST,
};
use gateway::sns::SnsScanPublisher;

const LOCALSTACK_TAG: &str = "4.4";
const REGION: &str = "us-east-1";

async fn start_localstack() -> (ContainerAsync<GenericImage>, String) {
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
    (container, format!("http://127.0.0.1:{port}"))
}

fn dummy_credentials() -> Credentials {
    Credentials::new("test", "test", None, None, "localstack-test")
}

async fn sns_client(endpoint: &str) -> aws_sdk_sns::Client {
    let config = aws_sdk_sns::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(endpoint)
        .credentials_provider(dummy_credentials())
        .build();
    aws_sdk_sns::Client::from_conf(config)
}

async fn sqs_client(endpoint: &str) -> aws_sdk_sqs::Client {
    let config = aws_sdk_sqs::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(endpoint)
        .credentials_provider(dummy_credentials())
        .build();
    aws_sdk_sqs::Client::from_conf(config)
}

/// Crea un topic, una cola y la suscripción raw entre ambos; devuelve
/// `(topic_arn, queue_url)`.
async fn topic_with_queue(
    sns: &aws_sdk_sns::Client,
    sqs: &aws_sdk_sqs::Client,
    name: &str,
) -> (String, String) {
    let topic_arn = sns
        .create_topic()
        .name(name)
        .send()
        .await
        .expect("crear topic")
        .topic_arn
        .expect("topic arn");
    let queue_url = sqs
        .create_queue()
        .queue_name(name)
        .send()
        .await
        .expect("crear cola")
        .queue_url
        .expect("queue url");
    let queue_arn = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .expect("atributos de la cola")
        .attributes
        .expect("atributos")
        .remove(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .expect("arn de la cola");
    sns.subscribe()
        .topic_arn(&topic_arn)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .expect("suscribir la cola al topic");
    (topic_arn, queue_url)
}

/// Recibe un mensaje de `queue_url` (long polling corto, reintentos).
async fn receive_one(sqs: &aws_sdk_sqs::Client, queue_url: &str) -> aws_sdk_sqs::types::Message {
    for _ in 0..10 {
        let out = sqs
            .receive_message()
            .queue_url(queue_url)
            .message_attribute_names("All")
            .wait_time_seconds(2)
            .max_number_of_messages(1)
            .send()
            .await
            .expect("recibir de la cola");
        if let Some(message) = out.messages.and_then(|m| m.into_iter().next()) {
            return message;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("no llegó ningún mensaje a la cola {queue_url}");
}

fn routing_key_of(message: &aws_sdk_sqs::types::Message) -> String {
    message
        .message_attributes()
        .and_then(|attrs| attrs.get("routing_key"))
        .and_then(|value| value.string_value())
        .expect("el mensaje debe traer el atributo routing_key")
        .to_string()
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishes_request_and_cancellation_with_body_and_routing_key_attribute() {
    let (_container, endpoint) = start_localstack().await;
    let sns = sns_client(&endpoint).await;
    let sqs = sqs_client(&endpoint).await;
    let (requests_arn, requests_queue) = topic_with_queue(&sns, &sqs, "scan-requests").await;
    let (cancellations_arn, cancellations_queue) =
        topic_with_queue(&sns, &sqs, "scan-cancellations").await;

    let publisher = SnsScanPublisher::from_client(sns, requests_arn, cancellations_arn);

    publisher
        .publish_scan_request(&ScanRequest {
            correlation_id: "corr-1".to_string(),
            ip: "192.0.2.10".to_string(),
            network_user: "netuser".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
            requested_by: "google-sub-123".to_string(),
        })
        .await
        .expect("publicar el ScanRequest");
    publisher
        .publish_scan_cancellation(&ScanCancellation {
            correlation_id: "corr-1".to_string(),
            requested_by: "google-sub-123".to_string(),
        })
        .await
        .expect("publicar el ScanCancellation");

    let request_msg = receive_one(&sqs, &requests_queue).await;
    let body: Value = serde_json::from_str(request_msg.body().expect("body")).expect("JSON");
    assert_eq!(
        body,
        json!({
            "correlation_id": "corr-1",
            "ip": "192.0.2.10",
            "network_user": "netuser",
            "ssh_credentials_ref": "lab-only-not-a-real-secret",
            "has_sudo": true,
            "requested_by": "google-sub-123",
        })
    );
    assert_eq!(routing_key_of(&request_msg), ROUTING_KEY_SCAN_REQUEST);

    let cancel_msg = receive_one(&sqs, &cancellations_queue).await;
    let body: Value = serde_json::from_str(cancel_msg.body().expect("body")).expect("JSON");
    assert_eq!(
        body,
        json!({"correlation_id": "corr-1", "requested_by": "google-sub-123"})
    );
    assert_eq!(routing_key_of(&cancel_msg), ROUTING_KEY_SCAN_CANCELLATION);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishing_to_a_missing_topic_yields_sns_publish_failed() {
    let (_container, endpoint) = start_localstack().await;
    let sns = sns_client(&endpoint).await;
    let missing = format!("arn:aws:sns:{REGION}:000000000000:no-existe");

    let publisher = SnsScanPublisher::from_client(sns, missing.clone(), missing);
    let err = publisher
        .publish_scan_cancellation(&ScanCancellation {
            correlation_id: "corr-1".to_string(),
            requested_by: "google-sub-123".to_string(),
        })
        .await
        .expect_err("publicar a un topic inexistente debe fallar");

    match err {
        BrokerError::SnsPublishFailed { topic, source } => {
            assert!(topic.ends_with("no-existe"));
            assert!(!source.to_string().is_empty());
        }
        other => panic!("variante inesperada: {other:?}"),
    }
}
