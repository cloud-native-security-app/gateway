//! Test de integración del composition root (`gateway::wiring::build`)
//! contra un LocalStack real (tarea MSG-GW-04): `build` debe conectar el
//! publicador SNS y el consumidor SQS a partir de la [`Config`], de modo que
//! lo publicado por `AppState::broker_publisher` llegue a los topics y que el
//! consumidor entregue al `handler` lo que haya en la cola de resultados.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use gateway::broker::{ScanOutcomeHandler, ScanRequest, ROUTING_KEY_SCAN_REQUEST};
use gateway::config::Config;
use gateway::domain::ScanOutcomeEvent;
use gateway::wiring;
use secrecy::SecretString;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

async fn serve_discovery(State(issuer_url): State<String>) -> Json<Value> {
    Json(json!({
        "issuer": issuer_url,
        "authorization_endpoint": format!("{issuer_url}/authorize"),
        "token_endpoint": format!("{issuer_url}/token"),
        "jwks_uri": format!("{issuer_url}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn serve_empty_jwks() -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(jsonwebtoken::jwk::JwkSet { keys: vec![] })
}

/// IdP OIDC de prueba mínimo: `wiring::build` hace el discovery OIDC.
async fn spawn_discovery_only_idp() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind del IdP");
    let issuer_url = format!("http://{}", listener.local_addr().expect("addr del IdP"));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(serve_discovery))
        .route("/jwks", get(serve_empty_jwks))
        .with_state(issuer_url.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.expect("IdP de prueba") });
    issuer_url
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

#[tokio::test]
#[ignore = "requiere Docker"]
async fn build_wires_the_sns_publisher_and_the_sqs_consumer() {
    let localstack = common::LocalStack::start().await;
    let (requests_arn, requests_queue) = localstack.topic_with_queue("scan-requests").await;
    let (cancellations_arn, _cancellations_queue) =
        localstack.topic_with_queue("scan-cancellations").await;
    let (outcomes_queue, outcomes_dlq) = localstack.outcomes_queue_with_dlq().await;

    // `connect` usa la cadena de credenciales por defecto de AWS.
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

    let issuer_url = spawn_discovery_only_idp().await;
    let config = Config {
        http_host: "127.0.0.1".to_string(),
        http_port: 0,
        google_client_id: "test-client-id".to_string(),
        google_client_secret: SecretString::from("lab-only-not-a-real-secret".to_string()),
        google_redirect_uri: "http://gateway.lab/auth/callback".to_string(),
        google_oidc_issuer_url: issuer_url,
        session_signing_key: SecretString::from("lab-only-not-a-real-secret".to_string()),
        session_ttl_secs: 3600,
        front_base_url: "https://front.lab".to_string(),
        front_origin: "https://front.lab".to_string(),
        ms_usuarios_base_url: "http://ms-usuarios.invalid".to_string(),
        ms_usuarios_shared_secret: SecretString::from("lab-only-not-a-real-secret".to_string()),
        scan_submission_rate_limit_max_requests: 1000,
        scan_submission_rate_limit_window_secs: 60,
        aws_region: common::REGION.to_string(),
        aws_endpoint_url: Some(localstack.endpoint.parse().expect("endpoint válido")),
        scan_requests_topic_arn: requests_arn,
        scan_cancellations_topic_arn: cancellations_arn,
        scan_outcomes_queue_url: outcomes_queue.parse().expect("queue url válida"),
        scan_outcomes_dlq_url: outcomes_dlq.parse().expect("dlq url válida"),
    };

    let built = wiring::build(config).await.expect("build debe completarse");

    // Publicación: AppState::broker_publisher -> SNS -> cola suscrita.
    built
        .state
        .broker_publisher
        .publish_scan_request(&ScanRequest {
            correlation_id: "corr-wiring".to_string(),
            ip: "192.0.2.10".to_string(),
            network_user: "netuser".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: false,
            requested_by: "google-sub-123".to_string(),
        })
        .await
        .expect("publicar a través del wiring");
    let delivered = localstack
        .receive_one(&requests_queue)
        .await
        .expect("el ScanRequest debe llegar a la cola suscrita");
    assert_eq!(common::routing_key_of(&delivered), ROUTING_KEY_SCAN_REQUEST);

    // Consumo: cola de resultados -> consumidor del wiring -> handler.
    localstack
        .send_with_routing_key(
            &outcomes_queue,
            "scan.outcome.started",
            r#"{"status":"started","correlation_id":"corr-wiring"}"#,
        )
        .await;
    let recorder = Arc::new(RecordingHandler::default());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(
        built
            .scan_outcome_consumer
            .run(recorder.clone(), shutdown.clone()),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while recorder.events.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "el consumidor no entregó el evento"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        recorder.events.lock().unwrap()[0],
        ScanOutcomeEvent::Started {
            correlation_id: "corr-wiring".to_string()
        }
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("el consumidor debe detenerse")
        .expect("sin panic");
}
