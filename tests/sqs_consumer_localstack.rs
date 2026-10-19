//! Test de integración de `SqsScanOutcomeConsumer` (tarea MSG-GW-03) contra
//! un LocalStack real levantado con `testcontainers` (sin mocks, sin cuenta
//! AWS): una cola fuente con `RedrivePolicy` (`maxReceiveCount: 3`) y
//! `VisibilityTimeout` corto, más su DLQ.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_sdk_sqs::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_sqs::types::{MessageAttributeValue, QueueAttributeName};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};
use tokio_util::sync::CancellationToken;

use gateway::broker::ScanOutcomeHandler;
use gateway::domain::ScanOutcomeEvent;
use gateway::sqs::SqsScanOutcomeConsumer;

const LOCALSTACK_TAG: &str = "4.4";
const REGION: &str = "us-east-1";
const VALID_BODY: &str = r#"{"status":"started","correlation_id":"corr-1"}"#;

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

fn sqs_client(endpoint: &str) -> aws_sdk_sqs::Client {
    let config = aws_sdk_sqs::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new(
            "test",
            "test",
            None,
            None,
            "localstack-test",
        ))
        .build();
    aws_sdk_sqs::Client::from_conf(config)
}

/// Crea la DLQ y la cola fuente (redrive tras 3 recepciones, visibilidad
/// `visibility_secs`); devuelve `(source_url, dlq_url)`.
async fn queues(sqs: &aws_sdk_sqs::Client, visibility_secs: u32) -> (String, String) {
    let dlq_url = sqs
        .create_queue()
        .queue_name("gateway-scan-outcomes-dlq")
        .send()
        .await
        .expect("crear DLQ")
        .queue_url
        .expect("url DLQ");
    let dlq_arn = sqs
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .expect("atributos DLQ")
        .attributes
        .expect("atributos")
        .remove(&QueueAttributeName::QueueArn)
        .expect("arn DLQ");
    let redrive = format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":3}}"#);
    let source_url = sqs
        .create_queue()
        .queue_name("gateway-scan-outcomes")
        .attributes(
            QueueAttributeName::VisibilityTimeout,
            visibility_secs.to_string(),
        )
        .attributes(QueueAttributeName::RedrivePolicy, redrive)
        .send()
        .await
        .expect("crear cola fuente")
        .queue_url
        .expect("url cola fuente");
    (source_url, dlq_url)
}

async fn send(sqs: &aws_sdk_sqs::Client, url: &str, body: &str) {
    sqs.send_message()
        .queue_url(url)
        .message_body(body)
        .message_attributes(
            "routing_key",
            MessageAttributeValue::builder()
                .data_type("String")
                .string_value("scan.outcome.started")
                .build()
                .expect("data_type presente"),
        )
        .send()
        .await
        .expect("enviar mensaje");
}

/// Mensajes visibles + en vuelo de `url`.
async fn pending(sqs: &aws_sdk_sqs::Client, url: &str) -> i64 {
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(url)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessages)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessagesNotVisible)
        .send()
        .await
        .expect("atributos de la cola")
        .attributes
        .expect("atributos");
    [
        QueueAttributeName::ApproximateNumberOfMessages,
        QueueAttributeName::ApproximateNumberOfMessagesNotVisible,
    ]
    .iter()
    .map(|k| attrs[k].parse::<i64>().expect("entero"))
    .sum()
}

/// Recibe un mensaje de `url` (reintentos hasta `attempts` long polls de 2 s).
async fn receive_one(
    sqs: &aws_sdk_sqs::Client,
    url: &str,
    attempts: u32,
) -> Option<aws_sdk_sqs::types::Message> {
    for _ in 0..attempts {
        let out = sqs
            .receive_message()
            .queue_url(url)
            .message_attribute_names("All")
            .wait_time_seconds(2)
            .max_number_of_messages(1)
            .send()
            .await
            .expect("recibir");
        if let Some(m) = out.messages.and_then(|m| m.into_iter().next()) {
            return Some(m);
        }
    }
    None
}

#[derive(Default)]
struct RecordingHandler {
    events: Mutex<Vec<ScanOutcomeEvent>>,
}

#[async_trait::async_trait]
impl ScanOutcomeHandler for RecordingHandler {
    async fn handle(&self, event: ScanOutcomeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl RecordingHandler {
    fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

/// Handler que avisa que empezó y nunca termina (simula un crash a mitad).
struct StuckHandler {
    started: tokio::sync::mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl ScanOutcomeHandler for StuckHandler {
    async fn handle(&self, _event: ScanOutcomeEvent) {
        let _ = self.started.send(());
        std::future::pending::<()>().await;
    }
}

async fn wait_until(mut cond: impl FnMut() -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "timeout esperando la condición");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn valid_outcome_is_handled_once_and_deleted() {
    let (_c, endpoint) = start_localstack().await;
    let sqs = sqs_client(&endpoint);
    let (source, dlq) = queues(&sqs, 2).await;
    send(&sqs, &source, VALID_BODY).await;

    let handler = Arc::new(RecordingHandler::default());
    let token = CancellationToken::new();
    let consumer = SqsScanOutcomeConsumer::from_client(sqs.clone(), source.clone(), dlq.clone());
    let task = tokio::spawn(consumer.run(handler.clone(), token.clone()));

    wait_until(|| handler.count() == 1, 20).await;
    // Pasa más de un VisibilityTimeout: si no se hubiera borrado, se reentregaría.
    tokio::time::sleep(Duration::from_secs(3)).await;
    token.cancel();
    task.await.expect("run termina");

    assert_eq!(handler.count(), 1, "exactamente una vez");
    assert_eq!(
        handler.events.lock().unwrap()[0],
        ScanOutcomeEvent::Started {
            correlation_id: "corr-1".to_string()
        }
    );
    assert_eq!(pending(&sqs, &source).await, 0, "cola fuente vacía");
    assert_eq!(pending(&sqs, &dlq).await, 0, "DLQ vacía");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn malformed_body_goes_to_dlq_with_routing_key_and_is_removed_from_source() {
    let (_c, endpoint) = start_localstack().await;
    let sqs = sqs_client(&endpoint);
    let (source, dlq) = queues(&sqs, 2).await;
    let bad = r#"{"status":"started","correlation_id":"c","extra":1}"#;
    send(&sqs, &source, bad).await;

    let handler = Arc::new(RecordingHandler::default());
    let token = CancellationToken::new();
    let consumer = SqsScanOutcomeConsumer::from_client(sqs.clone(), source.clone(), dlq.clone());
    let task = tokio::spawn(consumer.run(handler.clone(), token.clone()));

    let in_dlq = receive_one(&sqs, &dlq, 10)
        .await
        .expect("mensaje en la DLQ");
    assert_eq!(in_dlq.body(), Some(bad));
    let rk = in_dlq
        .message_attributes()
        .and_then(|a| a.get("routing_key"))
        .and_then(|v| v.string_value());
    assert_eq!(rk, Some("scan.outcome.started"));

    tokio::time::sleep(Duration::from_secs(3)).await;
    token.cancel();
    task.await.expect("run termina");
    assert_eq!(pending(&sqs, &source).await, 0, "fuera de la cola fuente");
    assert_eq!(handler.count(), 0, "el handler nunca se invoca");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn message_is_not_deleted_before_handle_completes() {
    let (_c, endpoint) = start_localstack().await;
    let sqs = sqs_client(&endpoint);
    let (source, dlq) = queues(&sqs, 2).await;
    send(&sqs, &source, VALID_BODY).await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let consumer = SqsScanOutcomeConsumer::from_client(sqs.clone(), source.clone(), dlq);
    let task = tokio::spawn(consumer.run(
        Arc::new(StuckHandler { started: tx }),
        CancellationToken::new(),
    ));
    rx.recv().await.expect("el handler empezó");

    // Crash a mitad de `handle`: la tarea se aborta sin que `handle` retorne.
    task.abort();
    let _ = task.await;

    let again = receive_one(&sqs, &source, 5)
        .await
        .expect("el mensaje se reentrega porque no se borró");
    assert_eq!(again.body(), Some(VALID_BODY));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn never_deleted_message_is_redriven_to_dlq_after_three_receives() {
    let (_c, endpoint) = start_localstack().await;
    let sqs = sqs_client(&endpoint);
    let (source, dlq) = queues(&sqs, 1).await;
    send(&sqs, &source, VALID_BODY).await;

    for n in 1..=3 {
        let m = receive_one(&sqs, &source, 5)
            .await
            .unwrap_or_else(|| panic!("recepción {n} sin mensaje"));
        assert_eq!(m.body(), Some(VALID_BODY));
        tokio::time::sleep(Duration::from_millis(1300)).await; // vence la visibilidad
    }
    // Una cuarta recepción ya no entrega: SQS mueve el mensaje a la DLQ.
    let _ = receive_one(&sqs, &source, 1).await;
    let moved = receive_one(&sqs, &dlq, 8).await.expect("mensaje en la DLQ");
    assert_eq!(moved.body(), Some(VALID_BODY));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn cancelling_the_token_stops_run_while_long_polling() {
    let (_c, endpoint) = start_localstack().await;
    let sqs = sqs_client(&endpoint);
    let (source, dlq) = queues(&sqs, 2).await;

    let token = CancellationToken::new();
    let consumer = SqsScanOutcomeConsumer::from_client(sqs, source, dlq);
    let task = tokio::spawn(consumer.run(Arc::new(RecordingHandler::default()), token.clone()));
    tokio::time::sleep(Duration::from_secs(1)).await; // ya en long poll

    let started = Instant::now();
    token.cancel();
    tokio::time::timeout(Duration::from_secs(25), task)
        .await
        .expect("run debe volver antes de 25 s")
        .expect("run no hace panic");
    assert!(started.elapsed() < Duration::from_secs(5));
}
