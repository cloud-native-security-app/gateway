//! Composition root de este Gateway: construye los clientes reales (OIDC,
//! `ms-usuarios`, Broker) desde [`Config`] y arma el [`AppState`]/consumidor
//! de fondo completos, listos para que [`crate::run`] los sirva.

use std::sync::Arc;
use std::time::Duration;

use crate::api::{AppState, ScanOwnershipRegistry, ScanSubmissionRateLimiter};
use crate::auth::{LoginStateStore, OidcClient};
use crate::broker::{BrokerConsumer, BrokerError, BrokerPublisher, ScanOutcomeHandler};
use crate::config::Config;
use crate::domain::ScanOutcomeEvent;
use crate::realtime::RealtimeRegistry;
use crate::usuarios_client::{ScanStatus, UsuariosClient, UsuariosClientError};

/// Audiencia (`aud`) embebida en la sesión propia que emite este Gateway:
/// identifica a este servicio (no a Google), fija y no configurable —
/// distinto de un secreto o de un detalle de despliegue (ver
/// `crate::config::Config`, que no expone un campo para esto).
const SESSION_AUDIENCE: &str = "gateway";
/// Emisor (`iss`) embebido en la sesión propia que emite este Gateway.
const SESSION_ISSUER: &str = "gateway";

/// Errores al construir la composición completa de este Gateway desde su
/// [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum WiringError {
    /// No se pudo completar el descubrimiento OIDC del proveedor de
    /// identidad.
    #[error("no se pudo completar el descubrimiento OIDC del proveedor de identidad")]
    Oidc(#[source] crate::auth::AuthError),
    /// No se pudo construir el cliente hacia `ms-usuarios`.
    #[error("no se pudo construir el cliente hacia el servicio de usuarios")]
    Usuarios(#[source] UsuariosClientError),
    /// No se pudo conectar al Broker (publicador o consumidor).
    #[error("no se pudo conectar al Broker")]
    Broker(#[source] BrokerError),
}

/// Resultado de construir la composición completa de este Gateway: el
/// [`AppState`] listo para [`crate::api::app_router`], y el consumidor de
/// fondo de `gateway.scan-outcomes` ya conectado (junto con el `handler` con
/// el que debe lanzarse, ver [`crate::broker::BrokerConsumer::run`]) —
/// pendiente únicamente de que [`crate::run`] lo lance con `tokio::spawn` y
/// sirva el router HTTP.
pub struct Wiring {
    /// Estado compartido del router HTTP de este Gateway.
    pub state: AppState,
    /// Consumidor de fondo de `gateway.scan-outcomes`, ya conectado.
    pub scan_outcome_consumer: BrokerConsumer,
    /// `handler` con el que se debe lanzar [`Self::scan_outcome_consumer`].
    pub scan_outcome_handler: Arc<dyn ScanOutcomeHandler>,
}

/// Construye la composición completa de este Gateway a partir de `config`
/// (consumida: sus credenciales se mueven a los clientes que las necesitan,
/// nunca se clonan — ver `docs/security-scope.md`).
///
/// Falla con [`WiringError`] si el descubrimiento OIDC, la construcción del
/// cliente hacia `ms-usuarios`, o la conexión al Broker (publicador o
/// consumidor) no se pudieron completar. Nunca entra en pánico.
pub async fn build(config: Config) -> Result<Wiring, WiringError> {
    let oidc_client = OidcClient::discover(
        &config.google_oidc_issuer_url,
        &config.google_client_id,
        &config.google_client_secret,
        &config.google_redirect_uri,
    )
    .await
    .map_err(WiringError::Oidc)?;

    let usuarios_client = Arc::new(
        UsuariosClient::new(
            config.ms_usuarios_base_url,
            config.ms_usuarios_shared_secret,
        )
        .map_err(WiringError::Usuarios)?,
    );

    let broker_publisher = Arc::new(
        BrokerPublisher::connect(&config.broker_amqps_url, &config.broker_vhost)
            .await
            .map_err(WiringError::Broker)?,
    );

    let scan_outcome_consumer =
        BrokerConsumer::connect(&config.broker_amqps_url, &config.broker_vhost)
            .await
            .map_err(WiringError::Broker)?;

    let scan_ownership = Arc::new(ScanOwnershipRegistry::new());
    let realtime = Arc::new(RealtimeRegistry::new());
    let scan_submission_rate_limiter = Arc::new(ScanSubmissionRateLimiter::new(
        config.scan_submission_rate_limit_max_requests,
        Duration::from_secs(config.scan_submission_rate_limit_window_secs),
    ));

    let scan_outcome_handler: Arc<dyn ScanOutcomeHandler> = Arc::new(ScanOutcomeRelay {
        usuarios_client: Arc::clone(&usuarios_client),
        scan_ownership: Arc::clone(&scan_ownership),
        realtime: Arc::clone(&realtime),
    });

    let state = AppState {
        oidc_client: Arc::new(oidc_client),
        login_states: Arc::new(LoginStateStore::new()),
        session_signing_key: config.session_signing_key,
        session_ttl_secs: config.session_ttl_secs,
        session_audience: SESSION_AUDIENCE.to_string(),
        session_issuer: SESSION_ISSUER.to_string(),
        usuarios_client,
        broker_publisher,
        scan_ownership,
        realtime,
        scan_submission_rate_limiter,
    };

    Ok(Wiring {
        state,
        scan_outcome_consumer,
        scan_outcome_handler,
    })
}

/// Puente entre el consumidor de fondo de `gateway.scan-outcomes`
/// ([`crate::broker::BrokerConsumer`]) y el resto de este Gateway (feature
/// `scan_outcome_relay`): por cada [`ScanOutcomeEvent`] ya confirmado
/// (`ack`) al Broker,
///
/// 1. lo relaya a cualquier stream SSE suscrito a su `correlation_id`
///    ([`RealtimeRegistry::publish`]), y
/// 2. si ese `correlation_id` tiene una [`crate::api::ScanOwnership`]
///    registrada (ver `crate::api::submit_scan`), actualiza su estado en
///    `ms-usuarios`.
///
/// Ambos pasos son best-effort: un fallo al actualizar `ms-usuarios`
/// (`ms-usuarios` caído, `scan_id` desconocido, etc.) se loggea y nunca
/// bloquea el relay SSE ni hace panic (criterio de aceptación de
/// `scan_outcome_relay`), igual que un `correlation_id` sin
/// `ScanOwnership` registrada (p. ej. el proceso se reinició entre `POST
/// /api/scans` y este evento, ver la limitación documentada en
/// [`ScanOwnershipRegistry`](crate::api::ScanOwnershipRegistry)).
struct ScanOutcomeRelay {
    usuarios_client: Arc<UsuariosClient>,
    scan_ownership: Arc<ScanOwnershipRegistry>,
    realtime: Arc<RealtimeRegistry>,
}

#[async_trait::async_trait]
impl ScanOutcomeHandler for ScanOutcomeRelay {
    async fn handle(&self, event: ScanOutcomeEvent) {
        self.realtime.publish(&event);

        let scan_id = event.correlation_id();
        let Some(ownership) = self.scan_ownership.lookup(scan_id) else {
            tracing::warn!(
                scan_id,
                "ScanOutcome recibido para un scan_id sin registro de propiedad; \
                 no se actualiza ms-usuarios (ver la limitación documentada de \
                 ScanOwnershipRegistry)"
            );
            return;
        };

        let status = match &event {
            ScanOutcomeEvent::Started { .. } => ScanStatus::EnProgreso,
            ScanOutcomeEvent::Completed { .. } => ScanStatus::Completado,
            ScanOutcomeEvent::Failed { .. } => ScanStatus::Fallido,
        };

        if let Err(err) = self
            .usuarios_client
            .update_scan_status(&ownership.owner, &ownership.ms_usuarios_scan_id, status)
            .await
        {
            tracing::error!(
                error = %err,
                scan_id,
                "no se pudo actualizar el estado del escaneo en ms-usuarios \
                 (best-effort, no bloquea el ack del mensaje ni el relay SSE)"
            );
        }
    }
}
