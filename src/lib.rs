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

/// Punto de entrada de la lógica del servicio, invocado desde `main`.
///
/// Por ahora solo deja constancia de arranque vía `tracing`; el resto del
/// servidor HTTP se incorpora en features posteriores.
pub async fn run() {
    tracing::info!("starting");
}
