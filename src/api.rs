//! Handlers y router `axum` de toda ruta pública de este Gateway.
//!
//! Expone las rutas de login/callback/logout OIDC (feature `oidc_login`),
//! una ruta de salud, `GET /api/me` (feature `session_middleware_and_me`) y
//! `GET /api/profile` (feature `usuarios_profile_proxy`), protegidas por el
//! middleware de sesión de [`crate::auth::require_session`]. El resto de
//! rutas públicas (escaneos, SSE, documentación) se añaden en features
//! posteriores.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::middleware;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::cookie::CookieJar;
use futures_util::Stream;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::auth::{self, AuthError, LoginStateStore, OidcClient, SessionValidator};
use crate::broker::{BrokerError, ScanCancellation, ScanRequest, ScanRequestPublisher};
use crate::domain::{ScanSubmission, ScanSubmissionError, Session};
use crate::realtime::RealtimeRegistry;
use crate::usuarios_client::{
    ScanHistoryEntry, ScanStatus, UserProfile, UsuariosClient, UsuariosClientError,
};

/// Entrada de [`ScanOwnershipRegistry`]: qué `scan_id` le asignó
/// `ms-usuarios` a la entrada de histórico de un `scanId` propio de este
/// Gateway, y qué sesión (usuario) lo generó.
#[derive(Clone)]
pub struct ScanOwnership {
    /// `scan_id` asignado por `ms-usuarios` (`ScanHistoryEntry::scan_id`,
    /// ver [`crate::usuarios_client::UsuariosClient::create_scan_history`]),
    /// distinto del `scanId`/`correlation_id` propio de este Gateway usado
    /// como clave de [`ScanOwnershipRegistry`].
    pub ms_usuarios_scan_id: String,
    /// Sesión (identidad ya verificada) que generó este `scanId` en `POST
    /// /api/scans` — usada tanto para llamar a `ms-usuarios` con la
    /// identidad correcta ([`crate::usuarios_client::UsuariosClient::update_scan_status`])
    /// como para verificar que solo su dueño puede suscribirse al stream SSE
    /// correspondiente (feature `scan_outcome_relay`, criterio de
    /// aceptación 4).
    pub owner: Session,
}

/// Registro en memoria, por `scanId`/`correlation_id` propio de este
/// Gateway, de a qué [`ScanOwnership`] pertenece cada solicitud de escaneo
/// en curso.
///
/// Poblado por `submit_scan` (handler de `POST /api/scans`, feature
/// `scan_submission`) justo después de registrar con éxito la entrada de
/// histórico en `ms-usuarios`, y
/// consultado tanto por el consumidor de `gateway.scan-outcomes` (feature
/// `scan_outcome_relay`, para saber qué `scan_id` de `ms-usuarios` y qué
/// identidad usar en `update_scan_status`) como por
/// `GET /api/scans/{scan_id}/events` (para verificar que el `scan_id`
/// solicitado pertenece a la sesión activa).
///
/// **Limitación conocida, aceptada, mismo patrón que
/// `auth::LoginStateStore`**: vive únicamente en la memoria de este
/// proceso — no sobrevive un reinicio ni se comparte entre instancias de
/// Gateway. No se persigue aquí una solución persistente (p. ej. recuperar
/// este mapeo consultando a `ms-usuarios`) porque está fuera del alcance de
/// esta feature y añadiría complejidad no pedida; si Gateway llega a
/// desplegarse con más de una instancia, o a necesitar sobrevivir un
/// restart mientras hay escaneos en curso, esto necesitará un store
/// compartido, a discutir como feature aparte si llega a hacer falta.
pub struct ScanOwnershipRegistry {
    entries: RwLock<HashMap<String, ScanOwnership>>,
}

impl ScanOwnershipRegistry {
    /// Registro vacío.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Registra que `scan_id` (propio de este Gateway) pertenece a `owner`,
    /// y que `ms-usuarios` lo identifica internamente como
    /// `ms_usuarios_scan_id`.
    pub fn register(&self, scan_id: &str, ms_usuarios_scan_id: String, owner: Session) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.insert(
            scan_id.to_string(),
            ScanOwnership {
                ms_usuarios_scan_id,
                owner,
            },
        );
    }

    /// Devuelve la [`ScanOwnership`] registrada para `scan_id`, si existe.
    pub fn lookup(&self, scan_id: &str) -> Option<ScanOwnership> {
        let entries = self
            .entries
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.get(scan_id).cloned()
    }

    /// Traduce en sentido inverso: dado `ms_usuarios_scan_id` (el `scan_id`
    /// que asigna `ms-usuarios` a una entrada de histórico, ver
    /// [`ScanOwnership::ms_usuarios_scan_id`]), devuelve el `scanId` propio
    /// de este Gateway que lo generó, si todavía está registrado (feature
    /// `scan_history_and_cancellation`, para traducir cada entrada del
    /// histórico de `ms-usuarios` al `scanId` que el cliente debe usar para
    /// suscribirse a `GET /api/scans/{scan_id}/events` o cancelar con `POST
    /// /api/scans/{scan_id}/cancel`).
    ///
    /// Recorrido lineal sobre el mapa: el volumen esperado es el de
    /// escaneos en curso de este proceso (no miles de entradas históricas),
    /// así que no se justifica mantener un segundo índice solo para esta
    /// consulta. Devuelve `None` si no hay ningún `scanId` registrado con ese
    /// `ms_usuarios_scan_id` — p. ej. porque el proceso se reinició desde que
    /// se publicó ese escaneo (misma limitación documentada en
    /// [`ScanOwnershipRegistry`]).
    pub fn lookup_by_ms_usuarios_scan_id(&self, ms_usuarios_scan_id: &str) -> Option<String> {
        let entries = self
            .entries
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        entries
            .iter()
            .find(|(_, ownership)| ownership.ms_usuarios_scan_id == ms_usuarios_scan_id)
            .map(|(scan_id, _)| scan_id.clone())
    }
}

impl Default for ScanOwnershipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Estado compartido por los handlers de autenticación de este router.
#[derive(Clone)]
pub struct AppState {
    /// Cliente OIDC ya resuelto contra el proveedor de identidad.
    pub oidc_client: Arc<OidcClient>,
    /// Store en memoria del `state`/`nonce`/PKCE de los logins en curso.
    pub login_states: Arc<LoginStateStore>,
    /// Clave de firma de la sesión propia de este Gateway.
    pub session_signing_key: SecretString,
    /// Tiempo de vida, en segundos, de la sesión propia emitida en login.
    pub session_ttl_secs: u64,
    /// Audiencia (`aud`) que se embebe en la sesión propia emitida.
    pub session_audience: String,
    /// Emisor (`iss`) que se embebe en la sesión propia emitida.
    pub session_issuer: String,
    /// Cliente HTTP hacia `ms-usuarios` (único módulo que le habla
    /// directamente, ver `docs/architecture.md` capa `usuarios_client`).
    pub usuarios_client: Arc<UsuariosClient>,
    /// Publicador de mensajes hacia el Broker (feature `scan_submission`).
    /// Guardado como `Arc<dyn ScanRequestPublisher>` para que los tests de
    /// otras features puedan inyectar un doble de prueba en vez de una
    /// conexión AMQPS real (ver `crate::broker::ScanRequestPublisher`).
    pub broker_publisher: Arc<dyn ScanRequestPublisher>,
    /// Registro en memoria de a qué sesión/`scan_id` de `ms-usuarios`
    /// pertenece cada `scanId` propio de este Gateway (feature
    /// `scan_outcome_relay`, ver [`ScanOwnershipRegistry`]).
    pub scan_ownership: Arc<ScanOwnershipRegistry>,
    /// Registro de streams SSE activos por `scanId` (feature
    /// `scan_outcome_relay`, ver [`crate::realtime::RealtimeRegistry`]).
    pub realtime: Arc<RealtimeRegistry>,
}

/// Construye el router `axum` con las rutas públicas de autenticación:
/// `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`.
///
/// `POST /auth/logout` queda deliberadamente fuera del middleware de sesión
/// (ver [`require_session`](crate::auth::require_session)): un logout debe
/// poder invocarse incluso con una sesión ya ausente/inválida/expirada, sin
/// que el middleware lo rechace con `401` antes de poder borrar la cookie
/// del navegador. Decisión documentada en `progress/impl_session_middleware_and_me.md`.
pub fn auth_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .with_state(state)
}

/// Construye el router `axum` con la ruta de salud pública de este Gateway
/// (`GET /health`), sin lógica de negocio ni dependencia de `AppState`.
pub fn health_router() -> Router {
    Router::new().route("/health", get(health))
}

/// Responde `200 OK` sin cuerpo: usado por orquestadores/balanceadores para
/// comprobar que el proceso está vivo, sin exigir sesión.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Construye el router `axum` con las rutas protegidas de este Gateway
/// (por ahora, solo `GET /api/me`), envueltas en el middleware de sesión
/// [`crate::auth::require_session`] (RNF-02): una request sin sesión propia
/// válida recibe `401` sin ejecutar ningún handler de este router.
fn protected_router(state: AppState) -> Router {
    let validator = SessionValidator::new(
        state.session_signing_key.clone(),
        state.session_audience.clone(),
        state.session_issuer.clone(),
    );

    Router::new()
        .route("/api/me", get(me))
        .route("/api/profile", get(profile))
        .route("/api/scans", post(submit_scan).get(list_scan_history))
        .route("/api/scans/:scan_id/events", get(scan_events))
        .route("/api/scans/:scan_id/cancel", post(cancel_scan))
        .layer(middleware::from_fn_with_state(
            validator,
            auth::require_session,
        ))
        .with_state(state)
}

/// Identidad de la sesión activa devuelta por `GET /api/me`.
///
/// No incluye `exp` ni ningún dato de codificación del JWT de sesión (`aud`/
/// `iss`): esos son un detalle de `auth`, no de la identidad expuesta a
/// `front`.
#[derive(Debug, Serialize)]
struct MeResponse {
    sub: String,
    email: String,
    name: String,
}

impl From<Session> for MeResponse {
    fn from(session: Session) -> Self {
        Self {
            sub: session.sub,
            email: session.email,
            name: session.name,
        }
    }
}

/// Devuelve la identidad (`sub`/`email`/`name`) de la sesión activa, ya
/// validada por el middleware de sesión. No consulta `ms-usuarios`: el
/// perfil completo del usuario es responsabilidad de una feature posterior
/// (`usuarios_profile_proxy`).
async fn me(Extension(session): Extension<Session>) -> Json<MeResponse> {
    Json(session.into())
}

/// Devuelve el perfil del usuario de la sesión activa, proxeando
/// `GET /users/me` de `ms-usuarios` a través de
/// [`crate::usuarios_client::UsuariosClient`] — único módulo de este repo
/// que le habla directamente (RF-09). Un fallo de red o un 5xx de
/// `ms-usuarios` se traduce en `502`/`504` sin exponer su URL interna en el
/// cuerpo de la respuesta (ver `docs/security-scope.md`).
async fn profile(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<UserProfile>, UsuariosClientError> {
    let profile = state.usuarios_client.get_profile(&session).await?;
    Ok(Json(profile))
}

/// Entrada del histórico de escaneos devuelta por `GET /api/scans` (RF-13):
/// los mismos datos que reporta `ms-usuarios` para esta entrada
/// (`target`/`status`/`requested_at`/`updated_at`), más el `scanId` propio de
/// este Gateway que generó esa entrada, si todavía se conoce.
///
/// **Limitación conocida, aceptada, mismo patrón que
/// [`ScanOwnershipRegistry`]**: `scan_id` viene de traducir el `scan_id` de
/// `ms-usuarios` vía [`ScanOwnershipRegistry::lookup_by_ms_usuarios_scan_id`],
/// que solo vive en la memoria de este proceso. Una entrada cuyo `scanId`
/// propio ya no está registrado (p. ej. el proceso se reinició desde que se
/// publicó ese escaneo) se devuelve igual, con `scan_id` ausente en el JSON
/// (`skip_serializing_if`) en vez de fallar o inventar un valor — el cliente
/// pierde la capacidad de reabrir el stream SSE o cancelar esa entrada
/// concreta hasta que vuelva a haber un `scanId` conocido para ella, pero
/// sigue viendo su histórico.
#[derive(Debug, Serialize)]
struct ScanHistoryEntryResponse {
    /// `scanId` propio de este Gateway (ver la nota de diseño de este tipo),
    /// ausente si no hay mapeo conocido en [`ScanOwnershipRegistry`].
    #[serde(rename = "scanId", skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    /// Objetivo del escaneo (IP o rango), tal como lo reporta `ms-usuarios`.
    target: String,
    /// Estado actual de la entrada, tal como lo reporta `ms-usuarios`.
    status: ScanStatus,
    /// Marca de tiempo (RFC 3339) en la que se solicitó el escaneo.
    requested_at: String,
    /// Marca de tiempo (RFC 3339) de la última actualización de estado.
    updated_at: String,
}

impl ScanHistoryEntryResponse {
    /// Construye la entrada de respuesta a partir de la [`ScanHistoryEntry`]
    /// que reportó `ms-usuarios`, traduciendo su `scan_id` interno al
    /// `scanId` propio de este Gateway vía `ownership` (ver la nota de
    /// diseño de este tipo).
    fn from_history_entry(entry: ScanHistoryEntry, ownership: &ScanOwnershipRegistry) -> Self {
        Self {
            scan_id: ownership.lookup_by_ms_usuarios_scan_id(&entry.scan_id),
            target: entry.target,
            status: entry.status,
            requested_at: entry.requested_at,
            updated_at: entry.updated_at,
        }
    }
}

/// Devuelve el histórico de escaneos del usuario de la sesión activa (RF-13),
/// proxeando `GET /users/me/scans` de `ms-usuarios` a través de
/// [`crate::usuarios_client::UsuariosClient`] — la autorización a nivel de
/// fila (un usuario solo ve su propio histórico) la aplica `ms-usuarios` a
/// partir de la identidad ya verificada que reenvía este handler, nunca un
/// identificador de otra fuente (ver `docs/security-scope.md`). Mismo mapeo
/// de errores que [`profile`].
async fn list_scan_history(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<Vec<ScanHistoryEntryResponse>>, UsuariosClientError> {
    let history = state.usuarios_client.list_scan_history(&session).await?;
    let response = history
        .into_iter()
        .map(|entry| ScanHistoryEntryResponse::from_history_entry(entry, &state.scan_ownership))
        .collect();
    Ok(Json(response))
}

/// Cuerpo de `POST /api/scans`: el objetivo (IP o rango CIDR) del escaneo
/// solicitado, sin validar todavía (ver [`ScanSubmission::parse`]).
#[derive(Debug, Deserialize)]
struct ScanSubmissionRequest {
    target: String,
}

/// Respuesta de `POST /api/scans` con éxito: el identificador de
/// seguimiento generado por este Gateway (RF-04), devuelto tan pronto se
/// confirma el registro de histórico y la publicación en el Broker, sin
/// esperar ningún desenlace del escaneo.
#[derive(Debug, Serialize)]
struct ScanSubmissionResponse {
    #[serde(rename = "scanId")]
    scan_id: String,
}

/// Errores de `POST /api/scans`, agregando los de cada capa involucrada
/// (validación pura de [`crate::domain`], `ms-usuarios`, el Broker) en un
/// único tipo con su propio mapeo a un status HTTP explícito.
#[derive(Debug, thiserror::Error)]
enum ScanSubmitError {
    /// El `target` recibido no es una IP ni un rango CIDR válido (RF-02/
    /// RF-03). No se llegó a tocar `ms-usuarios` ni el Broker.
    #[error(transparent)]
    InvalidTarget(#[from] ScanSubmissionError),
    /// Fallo al hablar con `ms-usuarios` (resolución de credenciales de red
    /// o registro/actualización de histórico).
    #[error(transparent)]
    Usuarios(#[from] UsuariosClientError),
    /// Fallo al publicar el `ScanRequest` en el Broker, después de haber
    /// registrado ya la entrada de histórico.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

/// Valida el objetivo del escaneo (RF-02/RF-03), resuelve
/// `network_user`/`ssh_credentials_ref`/`has_sudo` contra `ms-usuarios`
/// (feature `scan_submission`: esa API es especulativa mientras
/// `user-service` no la implemente, ver `docs/architecture.md`
/// §"Dependencia pendiente"), registra la entrada de histórico y publica el
/// `ScanRequest` correspondiente en el Broker.
///
/// Orden de operaciones, deliberado:
/// 1. Valida `target` — un formato inválido responde `400` sin ninguna
///    llamada externa.
/// 2. Genera el `scanId`/`correlation_id` propio de este Gateway, antes de
///    cualquier llamada externa (RF-04).
/// 3. Intenta resolver las credenciales de red — si la API no existe o no
///    hay credenciales configuradas, responde `501`/`422` sin registrar
///    histórico ni publicar nada.
/// 4. Registra el histórico (`Pendiente`) y publica el `ScanRequest`. Si la
///    publicación falla **después** de registrar el histórico, esa entrada
///    se actualiza a `Fallido` (best-effort: un fallo al marcarla se
///    loggea, nunca tumba la respuesta de error ya en curso) antes de
///    responder el error al cliente — nunca queda un `Pendiente` huérfano.
async fn submit_scan(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<ScanSubmissionRequest>,
) -> Result<Json<ScanSubmissionResponse>, ScanSubmitError> {
    let submission = ScanSubmission::parse(&body.target)?;

    let scan_id = uuid::Uuid::new_v4().to_string();

    let credentials = state
        .usuarios_client
        .resolve_scan_target(&session, &submission.target)
        .await?;

    let history_entry = state
        .usuarios_client
        .create_scan_history(&session, &submission.target)
        .await?;

    // Feature `scan_outcome_relay`: registra a quién pertenece este
    // `scanId` (sesión + `scan_id` asignado por `ms-usuarios`) justo después
    // de registrar el histórico con éxito, para que el consumidor de
    // `gateway.scan-outcomes` y el stream SSE puedan resolverlo más
    // adelante (ver `AppState::scan_ownership`). No altera el resto de esta
    // función, ya aprobada en la feature `scan_submission`.
    state
        .scan_ownership
        .register(&scan_id, history_entry.scan_id.clone(), session.clone());

    let scan_request = ScanRequest {
        correlation_id: scan_id.clone(),
        ip: submission.target,
        network_user: credentials.network_user,
        ssh_credentials_ref: credentials.ssh_credentials_ref,
        has_sudo: credentials.has_sudo,
        requested_by: session.sub.clone(),
    };

    if let Err(broker_err) = state
        .broker_publisher
        .publish_scan_request(&scan_request)
        .await
    {
        if let Err(mark_failed_err) = state
            .usuarios_client
            .update_scan_status(&session, &history_entry.scan_id, ScanStatus::Fallido)
            .await
        {
            tracing::error!(
                error = %mark_failed_err,
                scan_id = %history_entry.scan_id,
                "no se pudo marcar como Fallido el histórico tras un fallo de publicación en el Broker"
            );
        }
        return Err(broker_err.into());
    }

    Ok(Json(ScanSubmissionResponse { scan_id }))
}

/// Errores de `GET /api/scans/{scan_id}/events`.
#[derive(Debug, thiserror::Error)]
enum ScanEventsError {
    /// `scan_id` no tiene ninguna [`ScanOwnership`] registrada, o pertenece
    /// a una sesión distinta de la activa. Mismo status en ambos casos
    /// (`404`), para no revelar a un usuario que un `scan_id` ajeno existe
    /// (mismo criterio que exige la feature `scan_history_and_cancellation`
    /// para cancelar un scan ajeno).
    #[error("no existe un escaneo con ese identificador para la sesión activa")]
    NotFound,
}

impl IntoResponse for ScanEventsError {
    fn into_response(self) -> Response {
        tracing::debug!(error = %self, "solicitud de stream SSE rechazada");
        (StatusCode::NOT_FOUND, self.to_string()).into_response()
    }
}

/// Abre un stream SSE (`text/event-stream`) que emite cada
/// [`crate::domain::ScanOutcomeEvent`] nuevo de `scan_id` a medida que el
/// consumidor de `gateway.scan-outcomes` los recibe (RF-07/RF-08), hasta
/// alcanzar un estado terminal (`completed`/`failed`), momento en el que el
/// stream se cierra ordenadamente (ver [`crate::realtime::RealtimeRegistry::subscribe_stream`]).
///
/// Solo la sesión que generó `scan_id` (en `submit_scan`, el handler de
/// `POST /api/scans`) puede suscribirse: `scan_id` ausente en
/// [`AppState::scan_ownership`], o
/// perteneciente a otra sesión, responde `404` (nunca revela que un
/// `scan_id` ajeno existe, ver [`ScanEventsError::NotFound`]).
async fn scan_events(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(scan_id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ScanEventsError> {
    let ownership = state
        .scan_ownership
        .lookup(&scan_id)
        .ok_or(ScanEventsError::NotFound)?;

    if ownership.owner.sub != session.sub {
        return Err(ScanEventsError::NotFound);
    }

    Ok(Sse::new(state.realtime.subscribe_stream(scan_id)))
}

/// Errores de `POST /api/scans/{scan_id}/cancel`.
#[derive(Debug, thiserror::Error)]
enum ScanCancelError {
    /// `scan_id` no tiene ninguna [`ScanOwnership`] registrada, o pertenece a
    /// una sesión distinta de la activa. Mismo status en ambos casos
    /// (`404`), para no revelar a un usuario que un `scan_id` ajeno existe
    /// (mismo criterio que [`ScanEventsError::NotFound`]).
    #[error("no existe un escaneo con ese identificador para la sesión activa")]
    NotFound,
    /// El escaneo ya está en un estado terminal (`Completado`/`Fallido`) en
    /// `ms-usuarios`: no tiene sentido cancelarlo, y nunca se llega a
    /// publicar nada en el Broker para este caso.
    #[error("el escaneo ya finalizó y no puede cancelarse")]
    AlreadyTerminal,
    /// La entrada de histórico que `ms-usuarios` debería tener para
    /// [`ScanOwnership::ms_usuarios_scan_id`] no apareció en
    /// [`UsuariosClient::list_scan_history`] — inconsistencia del lado del
    /// servidor (p. ej. la entrada fue borrada), no un error del cliente.
    #[error("no se pudo confirmar el estado actual del escaneo antes de cancelarlo")]
    HistoryEntryMissing,
    /// Fallo al consultar `ms-usuarios` para conocer el estado actual del
    /// escaneo antes de decidir si cancelarlo.
    #[error(transparent)]
    Usuarios(#[from] UsuariosClientError),
    /// Fallo al publicar el `ScanCancellation` en el Broker.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl IntoResponse for ScanCancelError {
    fn into_response(self) -> Response {
        match self {
            ScanCancelError::NotFound => {
                tracing::debug!(error = %self, "solicitud de cancelación rechazada");
                (StatusCode::NOT_FOUND, self.to_string()).into_response()
            }
            ScanCancelError::AlreadyTerminal => {
                tracing::debug!(error = %self, "solicitud de cancelación rechazada");
                (StatusCode::CONFLICT, self.to_string()).into_response()
            }
            ScanCancelError::HistoryEntryMissing => {
                tracing::error!(error = %self, "inconsistencia de histórico al cancelar un escaneo");
                (StatusCode::BAD_GATEWAY, self.to_string()).into_response()
            }
            ScanCancelError::Usuarios(err) => err.into_response(),
            ScanCancelError::Broker(err) => {
                tracing::error!(error = %err, "fallo al publicar la cancelación de escaneo en el Broker");
                (
                    StatusCode::BAD_GATEWAY,
                    "no se pudo encolar la cancelación del escaneo".to_string(),
                )
                    .into_response()
            }
        }
    }
}

/// Cancela el escaneo `scan_id` (el `scanId` propio de este Gateway, RF-14):
/// verifica que pertenece a la sesión activa, consulta a `ms-usuarios` el
/// estado actual de su entrada de histórico y, si todavía no llegó a un
/// estado terminal, publica un [`ScanCancellation`] válido en
/// [`crate::broker::EXCHANGE_SCAN_CANCELLATIONS`].
///
/// Decisión de diseño: el estado "actual" se resuelve consultando a
/// `ms-usuarios` (vía [`UsuariosClient::list_scan_history`], buscando la
/// entrada cuyo `scan_id` coincide con
/// [`ScanOwnership::ms_usuarios_scan_id`]) en vez de rastrear un estado local
/// en [`ScanOwnershipRegistry`]/`AppState`: `ms-usuarios` ya es la fuente de
/// verdad del estado del histórico (lo actualiza el relay de
/// `gateway.scan-outcomes`, feature `scan_outcome_relay`), así que consultarlo
/// evita mantener un segundo estado que podría desincronizarse — más simple
/// de razonar, al costo de una llamada HTTP adicional antes de publicar.
///
/// - `scan_id` sin [`ScanOwnership`] registrada, o de otra sesión, responde
///   `404` ([`ScanCancelError::NotFound`], nunca revela que un `scan_id`
///   ajeno existe).
/// - Un escaneo ya `Completado`/`Fallido` responde `409`
///   ([`ScanCancelError::AlreadyTerminal`]) sin publicar nada en el Broker.
/// - En cualquier otro estado (`Pendiente`/`EnProgreso`), publica el
///   `ScanCancellation` (`correlation_id` = `scan_id` del path,
///   `requested_by` = `sub` de la sesión activa, nunca un identificador
///   reenviado sin verificar) y responde `202 Accepted`.
async fn cancel_scan(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(scan_id): Path<String>,
) -> Result<StatusCode, ScanCancelError> {
    let ownership = state
        .scan_ownership
        .lookup(&scan_id)
        .ok_or(ScanCancelError::NotFound)?;

    if ownership.owner.sub != session.sub {
        return Err(ScanCancelError::NotFound);
    }

    let history = state.usuarios_client.list_scan_history(&session).await?;
    let current_entry = history
        .into_iter()
        .find(|entry| entry.scan_id == ownership.ms_usuarios_scan_id)
        .ok_or(ScanCancelError::HistoryEntryMissing)?;

    if matches!(
        current_entry.status,
        ScanStatus::Completado | ScanStatus::Fallido
    ) {
        return Err(ScanCancelError::AlreadyTerminal);
    }

    let cancellation = ScanCancellation {
        correlation_id: scan_id,
        requested_by: session.sub,
    };

    state
        .broker_publisher
        .publish_scan_cancellation(&cancellation)
        .await?;

    Ok(StatusCode::ACCEPTED)
}

/// Descripción de una ruta expuesta por [`app_router`], usada tanto para
/// construirlo como para que los tests de la feature
/// `session_middleware_and_me` puedan enumerar el router completo y
/// verificar cuáles rutas llevan el middleware de sesión, en vez de
/// mantener esa lista duplicada a mano en cada test (criterio de
/// aceptación: "ninguna ruta nueva queda protegida o desprotegida por
/// accidente"). Si se añade una ruta a `app_router` sin añadir aquí su
/// entrada correspondiente, el test de enumeración deja de reflejar el
/// router real.
#[derive(Debug, Clone, Copy)]
pub struct RouteSpec {
    /// Método HTTP de la ruta.
    pub method: &'static str,
    /// Path de la ruta.
    pub path: &'static str,
    /// `true` si la ruta exige sesión válida (lleva
    /// [`crate::auth::require_session`]).
    pub protected: bool,
}

/// Tabla canónica de toda ruta expuesta por [`app_router`], fuente única de
/// verdad tanto para su construcción como para el test de enumeración de
/// rutas de la feature `session_middleware_and_me`.
pub const ROUTES: &[RouteSpec] = &[
    RouteSpec {
        method: "GET",
        path: "/auth/login",
        protected: false,
    },
    RouteSpec {
        method: "GET",
        path: "/auth/callback",
        protected: false,
    },
    RouteSpec {
        method: "POST",
        path: "/auth/logout",
        protected: false,
    },
    RouteSpec {
        method: "GET",
        path: "/health",
        protected: false,
    },
    RouteSpec {
        method: "GET",
        path: "/api/me",
        protected: true,
    },
    RouteSpec {
        method: "GET",
        path: "/api/profile",
        protected: true,
    },
    RouteSpec {
        method: "POST",
        path: "/api/scans",
        protected: true,
    },
    RouteSpec {
        method: "GET",
        path: "/api/scans",
        protected: true,
    },
    RouteSpec {
        method: "GET",
        path: "/api/scans/:scan_id/events",
        protected: true,
    },
    RouteSpec {
        method: "POST",
        path: "/api/scans/:scan_id/cancel",
        protected: true,
    },
];

/// Construye el router `axum` completo de este Gateway: las rutas públicas
/// de autenticación ([`auth_router`]), la ruta de salud ([`health_router`]),
/// y las rutas protegidas por el middleware de sesión
/// (`crate::auth::require_session`). Ver [`ROUTES`] para la tabla canónica
/// de qué ruta queda pública o protegida.
pub fn app_router(state: AppState) -> Router {
    auth_router(state.clone())
        .merge(health_router())
        .merge(protected_router(state))
}

/// Redirige (`302 Found`) al endpoint de autorización del proveedor de
/// identidad, tras registrar el `state`/`nonce`/PKCE de este intento de
/// login en [`AppState::login_states`].
async fn login(State(state): State<AppState>) -> Response {
    let login_start = state.oidc_client.begin_login();
    state.login_states.insert(
        &login_start.csrf_token,
        login_start.nonce,
        login_start.pkce_verifier,
    );

    redirect_found(&login_start.authorize_url)
}

/// Parámetros de consulta esperados en `GET /auth/callback`.
#[derive(Debug, Deserialize)]
struct CallbackParams {
    /// Código de autorización devuelto por el proveedor de identidad.
    #[serde(default)]
    code: Option<String>,
    /// Valor `state` devuelto por el proveedor de identidad, a validar
    /// contra el emitido en `/auth/login`.
    #[serde(default)]
    state: Option<String>,
}

/// Intercambia el código de autorización por tokens, valida el ID token del
/// proveedor de identidad y, si es válido, emite la sesión propia de este
/// Gateway como cookie `HttpOnly` + `Secure` + `SameSite=Strict`.
///
/// Rechaza el callback (sin crear sesión) si falta o no coincide el `state`
/// (mitigación CSRF), si falta el código, o si el ID token es inválido,
/// expiró, o tiene una audiencia/emisor/nonce inesperados.
async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AuthError> {
    let state_param = params.state.ok_or(AuthError::MissingState)?;
    let (nonce, pkce_verifier) = state
        .login_states
        .take(&state_param)
        .ok_or(AuthError::InvalidState)?;
    let code = params.code.ok_or(AuthError::MissingCode)?;

    let identity = state
        .oidc_client
        .exchange_and_verify(code, &nonce, pkce_verifier)
        .await?;

    let exp = current_epoch_secs().saturating_add(state.session_ttl_secs);
    let session = Session {
        sub: identity.sub,
        email: identity.email,
        name: identity.name,
        exp,
    };

    let token = auth::issue_session_token(
        &session,
        &state.session_signing_key,
        &state.session_audience,
        &state.session_issuer,
    )?;

    let cookie = auth::session_cookie(token, state.session_ttl_secs);
    Ok((jar.add(cookie), StatusCode::OK))
}

/// Borra la cookie de sesión del lado del navegador.
async fn logout(jar: CookieJar) -> (CookieJar, StatusCode) {
    (jar.remove(auth::removal_cookie()), StatusCode::NO_CONTENT)
}

/// Construye una respuesta `302 Found` con el header `Location` indicado.
///
/// Se construye a mano (en vez de `axum::response::Redirect::to`, que
/// responde `303 See Other`) porque el criterio de aceptación de esta
/// feature exige explícitamente un `302`.
fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Segundos transcurridos desde el epoch Unix, usados para calcular el
/// `exp` de la sesión emitida en login.
fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthError::MissingState
            | AuthError::InvalidState
            | AuthError::MissingCode
            | AuthError::TokenExchange
            | AuthError::MissingIdToken
            | AuthError::MissingIdentityClaim { .. } => StatusCode::BAD_REQUEST,
            AuthError::IdTokenExpired
            | AuthError::IdTokenInvalidSignature
            | AuthError::IdTokenInvalidAudienceOrIssuer
            | AuthError::IdTokenInvalidNonce
            | AuthError::IdTokenRejected
            | AuthError::SessionInvalid => StatusCode::UNAUTHORIZED,
            AuthError::Discovery | AuthError::SessionIssue => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::warn!(error = %self, %status, "fallo de autenticación");

        (status, self.to_string()).into_response()
    }
}

impl IntoResponse for UsuariosClientError {
    fn into_response(self) -> Response {
        let status = match &self {
            // Fallo de red/timeout hacia ms-usuarios: el Gateway no obtuvo
            // ninguna respuesta.
            UsuariosClientError::Unreachable => StatusCode::GATEWAY_TIMEOUT,
            // ms-usuarios respondió, pero con un status inesperado (incluye
            // 5xx propio y un 401 por credencial de servicio rechazada) o un
            // cuerpo 2xx que no se pudo interpretar.
            UsuariosClientError::UnexpectedResponse { .. }
            | UsuariosClientError::MalformedResponse => StatusCode::BAD_GATEWAY,
            // Fallo al construir la propia solicitud: un bug de este
            // Gateway, no de ms-usuarios.
            UsuariosClientError::RequestBuild => StatusCode::INTERNAL_SERVER_ERROR,
            // La API de ms-usuarios para resolver las credenciales de red de
            // un escaneo todavía no existe (ver `docs/architecture.md`
            // §"Dependencia pendiente") — error explícito, nunca un valor
            // inventado.
            UsuariosClientError::ScanTargetResolutionNotImplemented => StatusCode::NOT_IMPLEMENTED,
            // La API existe pero no hay credenciales de red configuradas
            // para este usuario/objetivo.
            UsuariosClientError::ScanTargetNotConfigured => StatusCode::UNPROCESSABLE_ENTITY,
        };

        tracing::warn!(error = %self, %status, "fallo al comunicarse con el servicio de usuarios");

        (status, self.to_string()).into_response()
    }
}

impl IntoResponse for ScanSubmitError {
    fn into_response(self) -> Response {
        match self {
            ScanSubmitError::InvalidTarget(err) => {
                tracing::debug!(error = %err, "solicitud de escaneo con IP/CIDR inválida");
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            ScanSubmitError::Usuarios(err) => err.into_response(),
            ScanSubmitError::Broker(err) => {
                tracing::error!(error = %err, "fallo al publicar la solicitud de escaneo en el Broker");
                (
                    StatusCode::BAD_GATEWAY,
                    "no se pudo encolar la solicitud de escaneo".to_string(),
                )
                    .into_response()
            }
        }
    }
}
