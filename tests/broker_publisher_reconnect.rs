//! Test de integración de la feature `broker_publisher_reconnect`.
//!
//! Reproduce exactamente el incidente confirmado en AWS: se fuerza el cierre
//! de la conexión AMQP subyacente de un [`BrokerPublisher`] ya conectado
//! (vía la Management HTTP API de `rabbitmq:4.3.5-management`, `DELETE
//! /api/connections/{name}` -- el usuario `gateway` no tiene permiso
//! `configure` para declarar nada por sí mismo, ver
//! `progress/explore_lapin_testcontainers.md` §3, pero cerrar su propia
//! conexión desde afuera no necesita ese permiso, así que esto es más
//! simple y determinista que reiniciar el contenedor entero) y se confirma
//! que una publicación posterior tiene éxito **sin reiniciar el proceso**
//! (mismo `BrokerPublisher`, misma instancia) -- mismo patrón de
//! `testcontainers` que `tests/scan_submission.rs`/
//! `tests/scan_outcome_relay.rs` (ver `docs/verification.md` Nivel 3).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ConfirmSelectOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::tcp::OwnedTLSConfig;
use lapin::types::FieldTable;
use lapin::{Connection, ConnectionProperties};
use secrecy::SecretString;
use serde_json::Value;
use testcontainers::core::{IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use gateway::broker::{BrokerPublisher, ScanRequest, ScanRequestPublisher};

/// Credenciales de laboratorio del usuario RabbitMQ `gateway`, copiadas de
/// `broker/rabbitmq/README.md` (tabla "Credenciales de laboratorio") -- el
/// mismo usuario ya definido en `broker/rabbitmq/definitions.json`, con
/// permiso `write` solo sobre `scan.requests`/`scan.cancellations`.
const GATEWAY_RABBITMQ_USER: &str = "gateway";
const GATEWAY_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret-gateway";

/// Credenciales de laboratorio del usuario administrador de RabbitMQ, único
/// con permiso para declarar/bindear la cola de verificación de este test y
/// para usar la Management HTTP API (tag `administrator`).
const ADMIN_RABBITMQ_USER: &str = "lab-admin";
const ADMIN_RABBITMQ_PASSWORD: &str = "lab-only-not-a-real-secret";

const VHOST: &str = "security-app";

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

static CRYPTO_PROVIDER_INIT: Once = Once::new();

fn install_crypto_provider_once() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        // Instalación defensiva del backend criptográfico de `rustls`, ver
        // `progress/explore_lapin_testcontainers.md` §4.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Levanta un `rabbitmq:4.3.5-management` real vía `testcontainers`, con la
/// topología copiada literalmente de `broker/rabbitmq/definitions.json` (ver
/// `docs/architecture.md`), TLS con los certificados de laboratorio también
/// copiados de `broker/rabbitmq/tls/`, y el puerto de la Management HTTP API
/// (15672) publicado -- usado por este test para forzar el cierre de la
/// conexión AMQP del publicador bajo prueba.
async fn start_rabbitmq() -> ContainerAsync<GenericImage> {
    install_crypto_provider_once();

    GenericImage::new("rabbitmq", "4.3.5-management")
        .with_exposed_port(5671.tcp())
        .with_exposed_port(15672.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Server startup complete"))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/definitions.json")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/definitions.json",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/rabbitmq.conf")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/rabbitmq.conf",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/ca_certificate.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/ca_certificate.pem",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/server_certificate.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/server_certificate.pem",
        ))
        .with_mount(Mount::bind_mount(
            fixture_path("rabbitmq/tls/server_key.pem")
                .to_string_lossy()
                .into_owned(),
            "/etc/rabbitmq/tls/server_key.pem",
        ))
        .start()
        .await
        .expect("el contenedor RabbitMQ de test debe arrancar")
}

/// Conexión AMQPS "a mano" (sin pasar por `gateway::broker`, que solo
/// expone publicar) usada por el test para preparar/leer la cola de
/// verificación con el usuario `lab-admin` (el usuario `gateway` tiene
/// `configure: "^$"`, no puede declarar nada).
async fn connect_lapin_as(
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    ca_pem: &str,
) -> Connection {
    let uri = format!("amqps://{user}:{password}@{host}:{port}/{VHOST}");
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);
    let tls_config = OwnedTLSConfig {
        identity: None,
        cert_chain: Some(ca_pem.to_string()),
    };

    Connection::connect_with_config(&uri, options, tls_config)
        .await
        .expect("la conexión AMQPS de prueba debe completarse")
}

/// Busca, vía la Management HTTP API, la conexión AMQP abierta por el
/// usuario `gateway` contra `VHOST`, y la cierra forzosamente -- la forma
/// más simple y determinista de reproducir "RabbitMQ le cerró la conexión a
/// `gateway`" (p. ej. porque ECS reemplazó la task de RabbitMQ) sin
/// reiniciar el contenedor entero.
async fn force_close_gateway_connection(http: &reqwest::Client, host: &str, management_port: u16) {
    // La Management HTTP API recolecta sus estadísticas (incluida la lista
    // de conexiones) de forma periódica, no instantánea al conectar -- se
    // sondea con un timeout acotado en vez de asumir que ya está disponible
    // inmediatamente después de `BrokerPublisher::connect_with_ca_pem`.
    let deadline = Instant::now() + Duration::from_secs(15);
    let connection_name = loop {
        let connections: Vec<Value> = http
            .get(format!("http://{host}:{management_port}/api/connections"))
            .basic_auth(ADMIN_RABBITMQ_USER, Some(ADMIN_RABBITMQ_PASSWORD))
            .send()
            .await
            .expect("la Management HTTP API debe responder a GET /api/connections")
            .json()
            .await
            .expect("la respuesta de /api/connections debe ser JSON válido");

        let found = connections
            .iter()
            .find(|connection| {
                connection["user"] == Value::String(GATEWAY_RABBITMQ_USER.to_string())
                    && connection["vhost"] == Value::String(VHOST.to_string())
            })
            .and_then(|connection| connection["name"].as_str())
            .map(str::to_string);

        if let Some(name) = found {
            break name;
        }

        assert!(
            Instant::now() < deadline,
            "la Management HTTP API nunca listó la conexión del usuario gateway"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let mut delete_url =
        url::Url::parse(&format!("http://{host}:{management_port}/api/connections"))
            .expect("URL base de la Management HTTP API debe parsear");
    delete_url
        .path_segments_mut()
        .expect("la URL base debe admitir segmentos de path")
        .push(&connection_name);

    let response = http
        .delete(delete_url)
        .basic_auth(ADMIN_RABBITMQ_USER, Some(ADMIN_RABBITMQ_PASSWORD))
        .send()
        .await
        .expect("DELETE /api/connections/{name} debe responder");

    assert!(
        response.status().is_success(),
        "cerrar la conexión del usuario gateway debe responder 2xx, fue {}",
        response.status()
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publisher_reconnects_and_a_later_publish_succeeds_without_restarting_the_process() {
    let container = start_rabbitmq().await;
    let host = container
        .get_host()
        .await
        .expect("host del contenedor de prueba")
        .to_string();
    let amqps_port = container
        .get_host_port_ipv4(5671.tcp())
        .await
        .expect("puerto AMQPS publicado del contenedor de prueba");
    let management_port = container
        .get_host_port_ipv4(15672.tcp())
        .await
        .expect("puerto de la Management HTTP API publicado del contenedor de prueba");

    let ca_pem = std::fs::read_to_string(fixture_path("rabbitmq/tls/ca_certificate.pem"))
        .expect("debe poder leer la CA de laboratorio");

    // Conexión de administración: declara y bindea la cola de verificación
    // ad-hoc de este test (nunca la declara el código de producción, que
    // usa el usuario `gateway`, sin permiso `configure`).
    let admin_connection = connect_lapin_as(
        ADMIN_RABBITMQ_USER,
        ADMIN_RABBITMQ_PASSWORD,
        &host,
        amqps_port,
        &ca_pem,
    )
    .await;
    let admin_channel = admin_connection
        .create_channel()
        .await
        .expect("canal de administración de prueba");

    admin_channel
        .queue_declare(
            "test.broker-publisher-reconnect-verify",
            QueueDeclareOptions {
                durable: false,
                exclusive: true,
                auto_delete: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("declarar la cola de verificación de prueba");

    admin_channel
        .queue_bind(
            "test.broker-publisher-reconnect-verify",
            "scan.requests",
            "scan.request",
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("bindear la cola de verificación de prueba");

    admin_channel
        .confirm_select(ConfirmSelectOptions::default())
        .await
        .expect("confirm_select del canal de administración");

    let mut consumer = admin_channel
        .basic_consume(
            "test.broker-publisher-reconnect-verify",
            "test-consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("consumir la cola de verificación de prueba");

    // El publicador bajo prueba: misma instancia de principio a fin de este
    // test -- nunca se reconstruye ni se reinicia ningún proceso.
    let publisher = BrokerPublisher::connect_with_ca_pem(
        &SecretString::from(format!(
            "amqps://{GATEWAY_RABBITMQ_USER}:{GATEWAY_RABBITMQ_PASSWORD}@{host}:{amqps_port}"
        )),
        VHOST,
        ca_pem,
    )
    .await
    .expect("BrokerPublisher debe poder conectar contra el RabbitMQ de prueba");

    assert!(
        publisher.is_connected().await,
        "la conexión inicial debe quedar activa"
    );

    let http = reqwest::Client::new();
    force_close_gateway_connection(&http, &host, management_port).await;

    // Espera (acotada) a que la conexión AMQP del publicador refleje el
    // cierre forzado -- determinista en vez de una publicación inmediata
    // "a ciegas", para que este test ejerza de verdad el camino de
    // reconexión y no una simple condición de carrera favorable.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if !publisher.is_connected().await {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "la conexión del publicador no reflejó el cierre forzado a tiempo"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let request = ScanRequest {
        correlation_id: "scan-reconnect-1".to_string(),
        ip: "192.0.2.20".to_string(),
        network_user: "netuser-lab".to_string(),
        ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
        has_sudo: false,
        requested_by: "google-sub-reconnect".to_string(),
    };

    publisher.publish_scan_request(&request).await.expect(
        "la publicación posterior al corte de conexión debe tener éxito gracias a la \
             reconexión automática, sin reiniciar el proceso",
    );

    assert!(
        publisher.is_connected().await,
        "tras reconectar, la conexión vigente debe quedar activa de nuevo"
    );

    let delivery = tokio::time::timeout(Duration::from_secs(10), consumer.next())
        .await
        .expect("no debe hacer timeout esperando el ScanRequest publicado tras reconectar")
        .expect("debe llegar un mensaje a la cola de verificación")
        .expect("sin error de protocolo AMQP");

    let scan_request: HashMap<String, Value> =
        serde_json::from_slice(&delivery.data).expect("el mensaje debe ser JSON válido");

    assert_eq!(
        scan_request["correlation_id"],
        Value::String(request.correlation_id.clone())
    );
    assert_eq!(scan_request["ip"], Value::String(request.ip.clone()));
    assert_eq!(
        scan_request["network_user"],
        Value::String(request.network_user.clone())
    );
    assert_eq!(
        scan_request["ssh_credentials_ref"],
        Value::String(request.ssh_credentials_ref.clone())
    );
    assert_eq!(scan_request["has_sudo"], Value::Bool(request.has_sudo));
    assert_eq!(
        scan_request["requested_by"],
        Value::String(request.requested_by.clone())
    );

    delivery
        .acker
        .ack(BasicAckOptions::default())
        .await
        .expect("debe poder confirmar el mensaje consumido");
}
