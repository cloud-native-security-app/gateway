//! Handshake OIDC contra el proveedor de identidad (Google en producción, un
//! IdP de prueba en tests de integración), y emisión de la sesión propia de
//! este Gateway (`jsonwebtoken`).
//!
//! El ID token de Google se valida una sola vez, aquí, durante el callback
//! de login, y se descarta inmediatamente tras extraer la identidad: nunca
//! se persiste, se loggea, ni se reenvía (ver `docs/security-scope.md`). El
//! middleware `axum` que exige sesión propia válida en rutas protegidas es
//! responsabilidad de una feature posterior (`session_middleware_and_me`):
//! este módulo solo emite/describe la sesión, no la vuelve a validar.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum_extra::extract::cookie::{Cookie, SameSite};
use cookie::time::Duration as CookieDuration;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::domain::Session;

/// Nombre de la cookie que transporta la sesión propia firmada de este
/// Gateway.
pub const SESSION_COOKIE_NAME: &str = "gateway_session";

/// Tiempo máximo que un intento de login (entre `GET /auth/login` y
/// `GET /auth/callback`) puede permanecer pendiente en [`LoginStateStore`]
/// antes de considerarse expirado.
const LOGIN_STATE_TTL: Duration = Duration::from_secs(600);

/// Tipo concreto de [`CoreClient`] tras construirlo desde el documento de
/// discovery: el endpoint de autorización queda fijado (`EndpointSet`), y el
/// resto de endpoints opcionales de OIDC Core (`device_authorization`,
/// `introspection`, `revocation`) no se usan en este Gateway
/// (`EndpointNotSet`). `token`/`userinfo` quedan `EndpointMaybeSet` porque
/// el propio tipo de `openidconnect` no puede garantizar en tiempo de
/// compilación que el documento de discovery los incluya.
type ConfiguredCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Errores del handshake OIDC contra el proveedor de identidad y de la
/// emisión de la sesión propia de este Gateway.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No se pudo completar el descubrimiento OIDC del proveedor de
    /// identidad (documento `.well-known/openid-configuration` o su JWKS).
    #[error("no se pudo completar el descubrimiento OIDC del proveedor de identidad")]
    Discovery,
    /// No se pudo intercambiar el código de autorización por tokens.
    #[error("no se pudo intercambiar el código de autorización por tokens")]
    TokenExchange,
    /// El proveedor de identidad no devolvió un ID token en la respuesta de
    /// token.
    #[error("el proveedor de identidad no devolvió un ID token")]
    MissingIdToken,
    /// El ID token está vencido (`exp`).
    #[error("el ID token está vencido")]
    IdTokenExpired,
    /// La firma del ID token es inválida (no verifica contra el JWKS del
    /// proveedor).
    #[error("la firma del ID token es inválida")]
    IdTokenInvalidSignature,
    /// El ID token tiene una audiencia (`aud`) o emisor (`iss`) inesperados.
    #[error("el ID token tiene una audiencia o emisor inesperados")]
    IdTokenInvalidAudienceOrIssuer,
    /// El `nonce` del ID token no coincide con el generado en
    /// `/auth/login`.
    #[error("el nonce del ID token no coincide con el de la solicitud de login")]
    IdTokenInvalidNonce,
    /// El ID token no superó alguna otra verificación de identidad no
    /// cubierta por una variante más específica.
    #[error("el ID token no superó la verificación de identidad")]
    IdTokenRejected,
    /// Falta un claim de identidad requerido (p. ej. `email`) en el ID
    /// token.
    #[error("falta el claim requerido `{claim}` en el ID token")]
    MissingIdentityClaim {
        /// Nombre del claim ausente.
        claim: &'static str,
    },
    /// Falta el parámetro `state` en el callback de login.
    #[error("falta el parámetro state en el callback de login")]
    MissingState,
    /// El parámetro `state` no coincide con ningún login vigente (mitigación
    /// CSRF) o el intento de login ya expiró.
    #[error("el parámetro state no coincide con ningún login vigente")]
    InvalidState,
    /// Falta el parámetro `code` en el callback de login.
    #[error("falta el parámetro code en el callback de login")]
    MissingCode,
    /// No se pudo firmar la sesión propia de este Gateway.
    #[error("no se pudo emitir la sesión propia")]
    SessionIssue,
}

impl From<ClaimsVerificationError> for AuthError {
    fn from(err: ClaimsVerificationError) -> Self {
        match err {
            ClaimsVerificationError::Expired(_) => AuthError::IdTokenExpired,
            ClaimsVerificationError::InvalidAudience(_)
            | ClaimsVerificationError::InvalidIssuer(_) => {
                AuthError::IdTokenInvalidAudienceOrIssuer
            }
            ClaimsVerificationError::InvalidNonce(_) => AuthError::IdTokenInvalidNonce,
            ClaimsVerificationError::SignatureVerification(_) => AuthError::IdTokenInvalidSignature,
            // `ClaimsVerificationError` es `#[non_exhaustive]`: el resto de
            // variantes actuales (`InvalidAuthContext`, `InvalidAuthTime`,
            // `InvalidSubject`, `Other`, `Unsupported`) y cualquier variante
            // futura se tratan como un rechazo genérico de identidad.
            _ => AuthError::IdTokenRejected,
        }
    }
}

/// Identidad extraída de un ID token de Google ya validado (firma, `aud`,
/// `iss`, `exp`, `nonce`).
///
/// No incluye el propio ID token ni ningún otro dato crudo de Google: se
/// descarta inmediatamente tras esta extracción (ver
/// `docs/security-scope.md`).
#[derive(Debug, Clone)]
pub struct GoogleIdentity {
    /// Identificador estable del usuario en Google (`sub`).
    pub sub: String,
    /// Correo electrónico reportado por Google.
    pub email: String,
    /// Nombre para mostrar reportado por Google (cadena vacía si Google no
    /// lo incluyó en el ID token).
    pub name: String,
}

/// Resultado de iniciar un login: la URL a la que redirigir al navegador, y
/// el material (`state`/`nonce`/PKCE) que debe sobrevivir hasta el callback
/// (ver [`LoginStateStore`]).
pub struct LoginStart {
    /// URL de autorización del proveedor de identidad a la que redirigir al
    /// navegador.
    pub authorize_url: String,
    /// Token anti-CSRF (`state`) generado para este intento de login.
    pub csrf_token: CsrfToken,
    /// Nonce asociado a este intento de login, verificado en el callback.
    pub nonce: Nonce,
    /// Verificador PKCE asociado a este intento de login.
    pub pkce_verifier: PkceCodeVerifier,
}

/// Cliente OIDC contra el proveedor de identidad (Google en producción, un
/// IdP de prueba en tests de integración), ya resuelto vía discovery.
pub struct OidcClient {
    core: ConfiguredCoreClient,
    http_client: openidconnect::reqwest::Client,
}

impl OidcClient {
    /// Descubre el proveedor OIDC en `issuer_url` (documento
    /// `.well-known/openid-configuration` + JWKS, obtenidos una sola vez
    /// aquí, no en cada validación posterior) y construye el cliente
    /// configurado con las credenciales de este Gateway.
    ///
    /// Falla con [`AuthError::Discovery`] si el descubrimiento no se pudo
    /// completar (red, documento inválido, `issuer` inconsistente, o
    /// `redirect_uri`/`issuer_url` mal formadas).
    pub async fn discover(
        issuer_url: &str,
        client_id: &str,
        client_secret: &SecretString,
        redirect_uri: &str,
    ) -> Result<Self, AuthError> {
        // Deshabilitar el seguimiento de redirects evita SSRF, tal como
        // advierte la propia documentación de `openidconnect`.
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AuthError::Discovery)?;

        let issuer = IssuerUrl::new(issuer_url.to_string()).map_err(|_| AuthError::Discovery)?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|_| AuthError::Discovery)?;

        let redirect =
            RedirectUrl::new(redirect_uri.to_string()).map_err(|_| AuthError::Discovery)?;

        let core = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.expose_secret().to_string())),
        )
        .set_redirect_uri(redirect);

        Ok(Self { core, http_client })
    }

    /// Genera la URL de autorización del proveedor de identidad para
    /// iniciar un login, junto con el `state`/`nonce`/PKCE que deben
    /// persistirse (ver [`LoginStateStore`]) hasta el callback.
    pub fn begin_login(&self) -> LoginStart {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (authorize_url, csrf_token, nonce) = self
            .core
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        LoginStart {
            authorize_url: authorize_url.to_string(),
            csrf_token,
            nonce,
            pkce_verifier,
        }
    }

    /// Intercambia `code` por tokens, valida el ID token devuelto (firma vía
    /// JWKS, `aud`, `iss`, `exp`, `nonce`) usando la crate `openidconnect`,
    /// y extrae la identidad verificada.
    ///
    /// El ID token se descarta inmediatamente después de esta llamada: no
    /// se persiste, no se loggea, no se reenvía (ver
    /// `docs/security-scope.md`).
    pub async fn exchange_and_verify(
        &self,
        code: String,
        nonce: &Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<GoogleIdentity, AuthError> {
        let token_response = self
            .core
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| AuthError::TokenExchange)?
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|_| AuthError::TokenExchange)?;

        let id_token = token_response.id_token().ok_or(AuthError::MissingIdToken)?;

        let verifier = self.core.id_token_verifier();
        let claims = id_token.claims(&verifier, nonce)?;

        let email = claims
            .email()
            .map(|email| email.as_str().to_string())
            .ok_or(AuthError::MissingIdentityClaim { claim: "email" })?;

        // `name` no es un claim garantizado por el estándar OIDC ni siquiera
        // con el scope `profile`; se usa cadena vacía si el proveedor no lo
        // envía, en vez de rechazar el login por esto.
        let name = claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_string())
            .unwrap_or_default();

        Ok(GoogleIdentity {
            sub: claims.subject().as_str().to_string(),
            email,
            name,
        })
    }
}

/// Entrada pendiente de un login en curso: el `nonce` y el verificador PKCE
/// asociados al `state` (CSRF) generado en `/auth/login`, más el momento en
/// que se creó (para expirar entradas abandonadas).
struct LoginStateEntry {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    created_at: Instant,
}

/// Store en memoria del `state`/`nonce`/PKCE de los logins en curso de este
/// proceso, con un TTL corto (`LOGIN_STATE_TTL`).
///
/// **Limitación conocida**: vive únicamente en la memoria de este proceso —
/// no sobrevive un reinicio ni se comparte entre instancias de Gateway. Es
/// una decisión de diseño simple, aceptable para esta feature (un `state`
/// de vida muy corta, pensado para un único proceso); si Gateway llega a
/// desplegarse con más de una instancia sin sesión pegajosa delante, esto
/// necesitará un store compartido (p. ej. Redis), a discutir como feature
/// aparte si llega a hacer falta.
pub struct LoginStateStore {
    entries: Mutex<HashMap<String, LoginStateEntry>>,
}

impl LoginStateStore {
    /// Crea un store vacío.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Registra un login en curso, identificado por el valor secreto del
    /// `state` (CSRF) generado en `/auth/login`.
    ///
    /// De paso, descarta entradas ya expiradas para no crecer sin límite con
    /// logins abandonados.
    pub fn insert(&self, csrf_token: &CsrfToken, nonce: Nonce, pkce_verifier: PkceCodeVerifier) {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, entry| now.duration_since(entry.created_at) < LOGIN_STATE_TTL);
        entries.insert(
            csrf_token.secret().clone(),
            LoginStateEntry {
                nonce,
                pkce_verifier,
                created_at: now,
            },
        );
    }

    /// Consume la entrada asociada a `state`, si existe y no expiró.
    ///
    /// Devuelve `None` si `state` no coincide con ningún login vigente
    /// (mitigación CSRF) o si expiró — en ambos casos el callback debe
    /// rechazarse sin crear sesión.
    pub fn take(&self, state: &str) -> Option<(Nonce, PkceCodeVerifier)> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entry = entries.remove(state)?;
        if Instant::now().duration_since(entry.created_at) >= LOGIN_STATE_TTL {
            return None;
        }
        Some((entry.nonce, entry.pkce_verifier))
    }
}

impl Default for LoginStateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Claims JWT de la sesión propia de este Gateway (formato de codificación
/// sobre el alambre), distinto del tipo de dominio [`Session`]: añade
/// `aud`/`iss`, que son un detalle de validación de este JWT concreto y no
/// parte de la identidad de negocio.
#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    sub: String,
    email: String,
    name: String,
    exp: u64,
    aud: String,
    iss: String,
}

/// Emite la sesión propia de este Gateway (JWT firmado con `jsonwebtoken`)
/// para `session`, lista para viajar como cookie (ver [`session_cookie`]).
///
/// `audience`/`issuer` identifican a este Gateway (no a Google): son lo que
/// se vuelve a validar en cada request a una ruta protegida (RNF-02,
/// feature `session_middleware_and_me`), no el ID token de Google. Falla
/// con [`AuthError::SessionIssue`] si la firma no se pudo generar.
pub fn issue_session_token(
    session: &Session,
    signing_key: &SecretString,
    audience: &str,
    issuer: &str,
) -> Result<String, AuthError> {
    let claims = SessionClaims {
        sub: session.sub.clone(),
        email: session.email.clone(),
        name: session.name.clone(),
        exp: session.exp,
        aud: audience.to_string(),
        iss: issuer.to_string(),
    };

    let encoding_key = EncodingKey::from_secret(signing_key.expose_secret().as_bytes());
    jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
        .map_err(|_| AuthError::SessionIssue)
}

/// Construye la cookie `Set-Cookie` que transporta `token` como sesión
/// propia de este Gateway: `HttpOnly`, `Secure`, `SameSite=Strict`, con el
/// mismo nombre y `path` que usa [`removal_cookie`] (necesario para que el
/// navegador la reconozca como la misma cookie y la pueda borrar en
/// logout).
pub fn session_cookie(token: String, ttl_secs: u64) -> Cookie<'static> {
    let ttl_secs = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
    Cookie::build((SESSION_COOKIE_NAME, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(CookieDuration::seconds(ttl_secs))
        .build()
}

/// Cookie de borrado de la sesión propia, para usar en `POST /auth/logout`.
///
/// Debe llevar el mismo nombre y `path` que [`session_cookie`] para que el
/// navegador la reconozca como la misma cookie y la elimine.
pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, "")).path("/").build()
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn lab_session() -> Session {
        Session {
            sub: "google-sub-123".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            exp: 9_999_999_999,
        }
    }

    #[test]
    fn issues_session_token_with_expected_claims() {
        let signing_key = SecretString::from("lab-only-not-a-real-secret".to_string());
        let session = lab_session();

        let token = issue_session_token(&session, &signing_key, "gateway", "gateway-issuer")
            .expect("debe poder firmar una sesión válida");

        let decoding_key = jsonwebtoken::DecodingKey::from_secret(b"lab-only-not-a-real-secret");
        let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
        validation.set_audience(&["gateway"]);
        validation.set_issuer(&["gateway-issuer"]);

        let decoded = jsonwebtoken::decode::<SessionClaims>(&token, &decoding_key, &validation)
            .expect("el token emitido debe decodificar con la misma clave");

        assert_eq!(decoded.claims.sub, session.sub);
        assert_eq!(decoded.claims.email, session.email);
        assert_eq!(decoded.claims.name, session.name);
        assert_eq!(decoded.claims.exp, session.exp);
        assert_eq!(decoded.claims.aud, "gateway");
        assert_eq!(decoded.claims.iss, "gateway-issuer");
    }

    #[test]
    fn session_cookie_has_hardened_attributes() {
        let cookie = session_cookie("some.jwt.token".to_string(), 3600);

        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert_eq!(cookie.value(), "some.jwt.token");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
    }

    #[test]
    fn removal_cookie_matches_session_cookie_name_and_path() {
        let removal = removal_cookie();

        assert_eq!(removal.name(), SESSION_COOKIE_NAME);
        assert_eq!(removal.path(), Some("/"));
    }

    #[test]
    fn login_state_store_round_trips_a_pending_login() {
        let store = LoginStateStore::new();
        let csrf_token = CsrfToken::new_random();
        let nonce = Nonce::new_random();
        let (_pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let expected_nonce_secret = nonce.secret().clone();

        store.insert(&csrf_token, nonce, pkce_verifier);

        let (recovered_nonce, _recovered_verifier) = store
            .take(csrf_token.secret())
            .expect("el state recién insertado debe recuperarse");

        assert_eq!(recovered_nonce.secret(), &expected_nonce_secret);
    }

    #[test]
    fn login_state_store_rejects_unknown_state() {
        let store = LoginStateStore::new();

        assert!(store.take("state-que-nunca-se-emitió").is_none());
    }

    #[test]
    fn login_state_store_take_is_single_use() {
        let store = LoginStateStore::new();
        let csrf_token = CsrfToken::new_random();
        let nonce = Nonce::new_random();
        let (_pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        store.insert(&csrf_token, nonce, pkce_verifier);
        assert!(store.take(csrf_token.secret()).is_some());
        assert!(
            store.take(csrf_token.secret()).is_none(),
            "un state ya consumido no debe poder reutilizarse"
        );
    }
}
