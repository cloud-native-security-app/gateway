//! Único módulo que conoce la URL y el contrato HTTP de `events-service`
//! (feature `admin_feed_proxy`): el servicio que lee el stream de Kinesis,
//! agrega las métricas del panel de administración y las sirve en
//! `GET /metrics` (snapshot JSON) y `GET /events` (SSE).
//!
//! El gateway ya no consume Kinesis: solo reenvía. Cada llamada lleva la
//! credencial de servicio compartida (`EVENTS_SERVICE_SHARED_SECRET`) en
//! [`GATEWAY_SECRET_HEADER_NAME`], el mismo patrón que hacia `ms-usuarios`.
//! La identidad del administrador no se reenvía: la autorización vive en el
//! gateway ([`crate::auth::require_admin`]).
//!
//! ## Decisiones de diseño
//!
//! - **Errores sin detalle**: [`EventsClientError`] nunca incluye la URL base
//!   ni la credencial; el estado exacto solo se loggea.
//! - **Métricas con timeout total; SSE solo con timeout de conexión**: un
//!   stream SSE vive horas, así que su petición no lleva timeout global.
//! - **Frames completos**: [`FrameBuffer`] acumula bytes y solo entrega
//!   frames SSE completos (terminados en línea en blanco), para que el
//!   gateway pueda intercalar su propio frame `closed` sin partir uno del
//!   upstream.

use std::pin::Pin;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};

pub use crate::usuarios_client::GATEWAY_SECRET_HEADER_NAME;

/// Timeout de conexión por defecto hacia `events-service`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Timeout total por defecto de `GET /metrics` (no aplica al SSE).
pub const DEFAULT_METRICS_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep-alive TCP, para detectar un upstream caído sin cerrar el socket.
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// Stream de trozos de bytes del `GET /events` de `events-service`.
pub type UpstreamBytes = Pin<Box<dyn Stream<Item = Result<Bytes, EventsClientError>> + Send>>;

/// Errores al llamar a `events-service`. Ninguno incluye la URL ni la
/// credencial.
#[derive(Debug, thiserror::Error)]
pub enum EventsClientError {
    /// No se pudo conectar o venció el timeout (se traduce a `503`).
    #[error("no se pudo contactar al servicio de eventos")]
    Unreachable,
    /// Respuesta no-2xx (incluye `401` por credencial rechazada) o cuerpo
    /// ilegible (se traduce a `502`).
    #[error("el servicio de eventos devolvió una respuesta inesperada")]
    UnexpectedResponse {
        /// Status HTTP recibido (`0` si falló la lectura del cuerpo).
        status: u16,
    },
    /// No se pudo construir el cliente HTTP.
    #[error("no se pudo construir el cliente hacia el servicio de eventos")]
    RequestBuild,
}

/// Cliente HTTP hacia `events-service`.
#[derive(Clone)]
pub struct EventsClient {
    http: Client,
    base_url: String,
    shared_secret: SecretString,
    metrics_timeout: Duration,
}

impl std::fmt::Debug for EventsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsClient").finish_non_exhaustive()
    }
}

impl EventsClient {
    /// Construye un cliente contra `base_url` autenticando con `shared_secret`.
    pub fn new(base_url: String, shared_secret: SecretString) -> Result<Self, EventsClientError> {
        Self::with_connect_timeout(base_url, shared_secret, DEFAULT_CONNECT_TIMEOUT)
    }

    /// Como [`Self::new`] con un timeout de conexión explícito (pruebas).
    pub fn with_connect_timeout(
        base_url: String,
        shared_secret: SecretString,
        connect_timeout: Duration,
    ) -> Result<Self, EventsClientError> {
        let http = Client::builder()
            .connect_timeout(connect_timeout)
            .tcp_keepalive(TCP_KEEPALIVE)
            .build()
            .map_err(|_| EventsClientError::RequestBuild)?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            shared_secret,
            metrics_timeout: DEFAULT_METRICS_TIMEOUT,
        })
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(format!("{}{path}", self.base_url)).header(
            GATEWAY_SECRET_HEADER_NAME,
            self.shared_secret.expose_secret(),
        )
    }

    /// `GET /metrics`: devuelve el cuerpo JSON tal cual (solo si `2xx`).
    pub async fn metrics(&self) -> Result<Bytes, EventsClientError> {
        let response = self
            .get("/metrics")
            .timeout(self.metrics_timeout)
            .send()
            .await
            .map_err(classify_send_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(unexpected(status));
        }
        response.bytes().await.map_err(|err| {
            if err.is_timeout() {
                EventsClientError::Unreachable
            } else {
                unexpected_body()
            }
        })
    }

    /// `GET /events`: abre el SSE y devuelve el stream de bytes crudos. Sin
    /// timeout global; un error de lectura posterior llega como `Err` en el
    /// stream.
    pub async fn open_events(&self) -> Result<UpstreamBytes, EventsClientError> {
        let response = self
            .get("/events")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .map_err(classify_send_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(unexpected(status));
        }
        Ok(Box::pin(
            response
                .bytes_stream()
                .map(|chunk| chunk.map_err(|_| unexpected_body())),
        ))
    }
}

fn classify_send_error(err: reqwest::Error) -> EventsClientError {
    tracing::warn!(
        kind = if err.is_timeout() {
            "timeout"
        } else {
            "connect"
        },
        "events-service inalcanzable"
    );
    EventsClientError::Unreachable
}

fn unexpected(status: StatusCode) -> EventsClientError {
    tracing::error!(
        status = status.as_u16(),
        "events-service devolvió un status inesperado"
    );
    EventsClientError::UnexpectedResponse {
        status: status.as_u16(),
    }
}

fn unexpected_body() -> EventsClientError {
    tracing::error!("falló la lectura del cuerpo de events-service");
    EventsClientError::UnexpectedResponse { status: 0 }
}

/// Acumula bytes y entrega solo frames SSE completos (hasta e incluyendo la
/// línea en blanco que los termina, `\n\n` o `\r\n\r\n`).
#[derive(Debug, Default)]
pub struct FrameBuffer {
    buf: BytesMut,
}

impl FrameBuffer {
    /// Buffer vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade `chunk` y devuelve los frames que quedaron completos, en orden.
    /// El resto (un frame a medias) se conserva para el siguiente trozo.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        self.buf.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(end) = frame_end(&self.buf) {
            frames.push(self.buf.split_to(end).freeze());
        }
        frames
    }
}

/// Posición (exclusiva) donde termina el primer frame completo, si lo hay.
fn frame_end(buf: &[u8]) -> Option<usize> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_emitted_only_when_complete_and_in_order() {
        let mut buffer = FrameBuffer::new();
        assert!(buffer.push(b"event: a\nda").is_empty());
        let frames = buffer.push(b"ta: 1\n\n: ping\n\nevent: b\n");
        assert_eq!(
            frames,
            vec![
                Bytes::from_static(b"event: a\ndata: 1\n\n"),
                Bytes::from_static(b": ping\n\n"),
            ]
        );
        assert_eq!(
            buffer.push(b"data: 2\n\n"),
            vec![Bytes::from_static(b"event: b\ndata: 2\n\n")]
        );
    }

    #[test]
    fn a_blank_line_split_between_chunks_still_completes_the_frame() {
        let mut buffer = FrameBuffer::new();
        assert!(buffer.push(b"event: a\ndata: 1\n").is_empty());
        assert_eq!(buffer.push(b"\n").len(), 1);
    }

    #[test]
    fn crlf_terminated_frames_are_supported() {
        let mut buffer = FrameBuffer::new();
        let frames = buffer.push(b"event: a\r\ndata: 1\r\n\r\n");
        assert_eq!(
            frames,
            vec![Bytes::from_static(b"event: a\r\ndata: 1\r\n\r\n")]
        );
    }
}
