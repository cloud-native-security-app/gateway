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
pub mod usuarios_client;
pub mod wiring;

use config::{Config, ConfigError};
use tokio::net::TcpListener;
use wiring::WiringError;

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
    /// `ms-usuarios`, Broker — ver [`crate::wiring::build`]).
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
/// completa de este Gateway ([`wiring::build`]), lanza el consumidor de
/// fondo de `gateway.scan-outcomes` (feature `scan_outcome_relay`, vive
/// mientras dure el proceso — ver `crate::broker::BrokerConsumer::run`) y
/// sirve el router HTTP completo (`crate::api::app_router`) hasta que el
/// proceso termine o el servidor falle.
pub async fn run() -> Result<(), RunError> {
    let config = Config::from_env()?;
    let http_host = config.http_host.clone();
    let http_port = config.http_port;

    let built = wiring::build(config).await?;

    tokio::spawn(built.scan_outcome_consumer.run(built.scan_outcome_handler));

    let app = api::app_router(built.state);
    let listener = TcpListener::bind((http_host.as_str(), http_port))
        .await
        .map_err(|source| RunError::Bind {
            host: http_host.clone(),
            port: http_port,
            source,
        })?;

    tracing::info!(%http_host, %http_port, "gateway escuchando");

    axum::serve(listener, app).await.map_err(RunError::Serve)
}
