//! API Manager / Gateway: único componente público de la plataforma.
//!
//! Este crate centraliza el login OIDC contra Google, el enrutamiento hacia
//! `ms-usuarios` y el Broker, el encolado de escaneos y el relay en tiempo
//! real de su avance. Ver `docs/architecture.md` para el detalle de cada
//! capa.

#![deny(missing_docs)]

pub mod api;
pub mod auth;
pub mod broker;
pub mod config;
pub mod domain;
pub mod realtime;
pub mod sns;
pub mod sqs;
pub mod usuarios_client;
pub mod wiring;

use std::time::Duration;

use config::{Config, ConfigError};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wiring::WiringError;

/// Tiempo máximo que se espera a que el consumidor SQS termine (un `handle`
/// en curso incluye una llamada HTTP a `ms-usuarios`) tras iniciar el
/// shutdown, antes de abortar su tarea.
const CONSUMER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Tiempo máximo que se espera a que las conexiones HTTP abiertas (p. ej.
/// streams SSE, que no terminan solos) se drenen tras la señal de shutdown.
/// Junto con `CONSUMER_SHUTDOWN_TIMEOUT` (10 s) queda por debajo de los 30 s que
/// ECS da entre `SIGTERM` y `SIGKILL`.
const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Errores posibles al arrancar el proceso completo de este Gateway,
/// devueltos por [`run`] a `main` (que los loggea y termina el proceso con
/// un código de salida distinto de cero, sin panics).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// La configuración desde variables de entorno no se pudo cargar (ver
    /// [`crate::config::Config::from_env`]).
    #[error("no se pudo cargar la configuración")]
    Config(#[from] ConfigError),
    /// No se pudo completar la composición de este Gateway (OIDC,
    /// `ms-usuarios`, SNS/SQS — ver [`crate::wiring::build`]).
    #[error("no se pudo completar la inicialización del servicio")]
    Wiring(#[from] WiringError),
    /// No se pudo abrir el socket TCP en el que escuchar (`HTTP_HOST`/
    /// `HTTP_PORT`).
    #[error("no se pudo escuchar en {host}:{port}")]
    Bind {
        /// Host configurado.
        host: String,
        /// Puerto configurado.
        port: u16,
        /// Error original del sistema operativo.
        #[source]
        source: std::io::Error,
    },
    /// El servidor HTTP terminó con un error (p. ej. un fallo irrecuperable
    /// de I/O al aceptar una conexión).
    #[error("el servidor HTTP terminó con un error")]
    Serve(#[source] std::io::Error),
}

/// Punto de entrada de la lógica del servicio, invocado desde `main`.
///
/// Carga la [`Config`] desde variables de entorno, construye la composición
/// completa de este Gateway ([`wiring::build`]), lanza el consumidor SQS de
/// fondo de la cola de resultados de escaneo (feature `scan_outcome_relay`,
/// ver [`crate::sqs::SqsScanOutcomeConsumer::run`]) y sirve el router HTTP
/// completo ([`crate::api::app_router`]).
///
/// ## Shutdown ordenado
///
/// ECS detiene la tarea con `SIGTERM` (y, en local, `Ctrl-C` envía `SIGINT`).
/// Al recibir cualquiera de las dos señales: (1) se cancela el
/// [`CancellationToken`] compartido con el consumidor, que deja de hacer long
/// polling de inmediato (un `handle` en curso termina antes; los mensajes sin
/// borrar reaparecen en la cola al vencer su visibilidad), (2) axum deja de
/// aceptar conexiones y drena las abiertas hasta `HTTP_DRAIN_TIMEOUT` (10 s) (los
/// streams SSE no terminan solos), y (3) se espera a la tarea del consumidor
/// hasta `CONSUMER_SHUTDOWN_TIMEOUT` (10 s), abortándola si no termina. Si el
/// servidor HTTP falla por su cuenta, el consumidor se detiene igual.
pub async fn run() -> Result<(), RunError> {
    let config = Config::from_env()?;
    let http_host = config.http_host.clone();
    let http_port = config.http_port;

    let built = wiring::build(config).await?;

    let shutdown = CancellationToken::new();
    let consumer = tokio::spawn(
        built
            .scan_outcome_consumer
            .run(built.scan_outcome_handler, shutdown.clone()),
    );

    let app = api::app_router(built.state);
    let listener = match TcpListener::bind((http_host.as_str(), http_port)).await {
        Ok(listener) => listener,
        Err(source) => {
            stop_consumer(&shutdown, consumer, CONSUMER_SHUTDOWN_TIMEOUT).await;
            return Err(RunError::Bind {
                host: http_host,
                port: http_port,
                source,
            });
        }
    };

    tracing::info!(%http_host, %http_port, "gateway escuchando");

    let signal_token = shutdown.clone();
    let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_signal().await;
        tracing::info!("señal de apagado recibida; deteniendo el servidor y el consumidor");
        signal_token.cancel();
    });
    let served = tokio::select! {
        result = serve => result,
        () = async {
            shutdown.cancelled().await;
            tokio::time::sleep(HTTP_DRAIN_TIMEOUT).await;
        } => {
            tracing::warn!("conexiones HTTP aún abiertas tras el tiempo de drenado; se cierran");
            Ok(())
        }
    };

    stop_consumer(&shutdown, consumer, CONSUMER_SHUTDOWN_TIMEOUT).await;
    served.map_err(RunError::Serve)
}

/// Se completa al recibir `Ctrl-C` (`SIGINT`) o, en Unix, `SIGTERM` (la señal
/// con la que ECS detiene una tarea).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "no se pudo instalar el manejador de Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "no se pudo instalar el manejador de SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Cancela `token` y espera hasta `timeout` a que la tarea del consumidor
/// termine; si no lo hace (o hace panic) la aborta. Devuelve `true` solo si
/// terminó limpiamente a tiempo.
async fn stop_consumer(
    token: &CancellationToken,
    mut handle: JoinHandle<()>,
    timeout: Duration,
) -> bool {
    token.cancel();
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(Ok(())) => {
            tracing::info!("consumidor SQS detenido");
            true
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, "la tarea del consumidor SQS terminó con error");
            false
        }
        Err(_) => {
            tracing::warn!("el consumidor SQS no terminó a tiempo; se aborta su tarea");
            handle.abort();
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test]
    async fn stop_consumer_cancels_the_token_and_waits_for_a_cooperative_task() {
        let token = CancellationToken::new();
        let task_token = token.clone();
        let handle = tokio::spawn(async move { task_token.cancelled().await });

        let clean = stop_consumer(&token, handle, Duration::from_secs(5)).await;

        assert!(
            clean,
            "una tarea que respeta el token debe parar limpiamente"
        );
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn stop_consumer_gives_up_after_the_timeout_and_aborts_a_stuck_task() {
        let token = CancellationToken::new();
        let handle = tokio::spawn(std::future::pending::<()>());

        let started = std::time::Instant::now();
        let clean = stop_consumer(&token, handle, Duration::from_millis(100)).await;

        assert!(
            !clean,
            "una tarea que ignora el token se reporta como no limpia"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
