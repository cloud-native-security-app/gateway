//! Handlers y router `axum` de toda ruta pública de este Gateway.
//!
//! Expone las rutas de login/callback/logout OIDC (feature `oidc_login`),
//! una ruta de salud, `GET /api/me` (feature `session_middleware_and_me`) y
//! `GET /api/profile` (feature `usuarios_profile_proxy`), protegidas por el
//! middleware de sesión de [`crate::auth::require_session`]. El resto de
//! rutas públicas (escaneos, SSE, documentación) se añaden en features
//! posteriores.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::cookie::CookieJar;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::auth::{self, AuthError, LoginStateStore, OidcClient, SessionValidator};
use crate::domain::Session;
use crate::usuarios_client::{UserProfile, UsuariosClient, UsuariosClientError};

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
        };

        tracing::warn!(error = %self, %status, "fallo al comunicarse con el servicio de usuarios");

        (status, self.to_string()).into_response()
    }
}
