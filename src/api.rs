//! Handlers y router `axum` de toda ruta pública de este Gateway.
//!
//! Por ahora solo expone las rutas de login/callback/logout OIDC (feature
//! `oidc_login`); el resto de rutas públicas (perfil, escaneos, SSE,
//! documentación) se añaden en features posteriores.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;

use crate::auth::{self, AuthError, LoginStateStore, OidcClient};
use crate::domain::Session;

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
}

/// Construye el router `axum` con las rutas públicas de autenticación:
/// `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`.
pub fn auth_router(state: AppState) -> Router {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .with_state(state)
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
            | AuthError::IdTokenRejected => StatusCode::UNAUTHORIZED,
            AuthError::Discovery | AuthError::SessionIssue => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::warn!(error = %self, %status, "fallo en el flujo de login OIDC");

        (status, self.to_string()).into_response()
    }
}
