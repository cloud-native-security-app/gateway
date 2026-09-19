//! Único módulo que conoce la URL y el contrato HTTP de `ms-usuarios`
//! (`docs/architecture.md`, capa `usuarios_client`): ningún otro módulo de
//! este repo hace una petición HTTP directa hacia `ms-usuarios`.
//!
//! ## Decisión de diseño: contrato asumido de `ms-usuarios`
//!
//! El contrato exacto de `GET`/`PUT /users/me` vive en
//! `user-service/docs/architecture.md` y `user-service/docs/security-scope.md`,
//! que **no** están disponibles en este checkout (son de otro repo). Para no
//! inventar aquí un shape de perfil que no está documentado (ver
//! `docs/architecture.md` §"Qué NO hacer" y `docs/security-scope.md`), este
//! cliente trata el perfil como JSON opaco ([`UserProfile`] = `serde_json::Value`):
//! lo reenvía tal cual llega de `ms-usuarios` a quien lo pida
//! ([`UsuariosClient::get_profile`]), y reenvía tal cual el cuerpo que se le
//! pide escribir en [`UsuariosClient::upsert_profile`]. Esta suposición debe
//! confirmarse contra el contrato real de `user-service` en cuanto esté
//! disponible en este checkout; mientras tanto, este cliente no asume ni
//! valida ningún campo concreto del perfil.
//!
//! Los nombres exactos de los headers de identidad
//! ([`FORWARDED_USER_HEADER_NAME`]) y de credencial de servicio
//! ([`GATEWAY_SECRET_HEADER_NAME`]) están confirmados contra el contrato real
//! de `user-service` (`user-service/src/api.rs`, constantes
//! `FORWARDED_USER_HEADER`/`GATEWAY_SECRET_HEADER`), no son una suposición de
//! este repo. El header de identidad transporta un JSON
//! `{"sub": "...", "email": "..."}` con la identidad ya verificada de la
//! sesión activa — nunca el JWT de sesión completo, nunca el token de Google
//! (ver `docs/security-scope.md`). Junto a él viaja la credencial de
//! servicio compartida (`MS_USUARIOS_SHARED_SECRET`) en
//! [`GATEWAY_SECRET_HEADER_NAME`].

use reqwest::{Client, RequestBuilder};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::domain::Session;

/// Nombre del header que transporta la identidad ya verificada de la sesión
/// activa hacia `ms-usuarios`, en formato JSON (`{"sub", "email"}`).
///
/// Confirmado contra el contrato real de `user-service`
/// (`user-service/src/api.rs::FORWARDED_USER_HEADER`), ver la nota de diseño
/// al inicio de este módulo.
pub const FORWARDED_USER_HEADER_NAME: &str = "X-Forwarded-User";

/// Nombre del header que transporta la credencial de servicio compartida
/// (`MS_USUARIOS_SHARED_SECRET`) hacia `ms-usuarios`.
///
/// Confirmado contra el contrato real de `user-service`
/// (`user-service/src/api.rs::GATEWAY_SECRET_HEADER`).
pub const GATEWAY_SECRET_HEADER_NAME: &str = "X-Gateway-Secret";

/// Perfil de usuario devuelto o enviado a `ms-usuarios`, tratado como JSON
/// opaco: ver la nota de diseño al inicio de este módulo sobre por qué este
/// cliente no tipa su contenido campo a campo.
pub type UserProfile = serde_json::Value;

/// Errores al llamar a `ms-usuarios` desde este cliente.
///
/// Ninguna variante incluye la URL base de `ms-usuarios` ni la credencial de
/// servicio en su mensaje (`docs/security-scope.md`): el detalle exacto solo
/// se loggea del lado del servidor (ver [`crate::api`]), nunca se expone en
/// el cuerpo de un error hacia `front`.
#[derive(Debug, thiserror::Error)]
pub enum UsuariosClientError {
    /// No se pudo contactar a `ms-usuarios` (red caída, timeout, TLS, DNS).
    #[error("no se pudo contactar al servicio de usuarios")]
    Unreachable,
    /// `ms-usuarios` respondió con un status HTTP no-2xx: incluye tanto un
    /// 401 por credencial de servicio rechazada como cualquier 5xx.
    #[error("el servicio de usuarios devolvió una respuesta inesperada")]
    UnexpectedResponse {
        /// Código de estado HTTP devuelto por `ms-usuarios`.
        status: u16,
    },
    /// El cuerpo de una respuesta 2xx de `ms-usuarios` no se pudo decodificar
    /// como JSON.
    #[error("no se pudo interpretar la respuesta del servicio de usuarios")]
    MalformedResponse,
    /// No se pudo construir la solicitud hacia `ms-usuarios` (p. ej. la
    /// identidad no se pudo serializar en el header correspondiente, o el
    /// cliente HTTP no se pudo inicializar).
    #[error("no se pudo construir la solicitud hacia el servicio de usuarios")]
    RequestBuild,
}

/// Cuerpo del header [`FORWARDED_USER_HEADER_NAME`]: la identidad ya
/// verificada de la sesión activa, nunca el JWT de sesión completo ni el
/// token de Google.
#[derive(Debug, Serialize)]
struct IdentityHeaderPayload<'a> {
    sub: &'a str,
    email: &'a str,
}

/// Cliente HTTP hacia `ms-usuarios`: único punto de este repo que conoce su
/// URL base y reenvía en cada llamada la identidad ya verificada de la
/// sesión activa junto con la credencial de servicio compartida (ver la nota
/// de diseño al inicio de este módulo y `docs/security-scope.md`).
#[derive(Clone)]
pub struct UsuariosClient {
    http: Client,
    base_url: String,
    shared_secret: SecretString,
}

impl UsuariosClient {
    /// Construye un cliente contra `base_url` (nunca expuesta a `front`),
    /// autenticando cada llamada con `shared_secret`.
    ///
    /// Falla con [`UsuariosClientError::RequestBuild`] si el backend TLS del
    /// cliente HTTP no se pudo inicializar (no debería ocurrir con la
    /// configuración `rustls-tls` por defecto de este crate, pero se
    /// propaga en vez de entrar en pánico).
    pub fn new(base_url: String, shared_secret: SecretString) -> Result<Self, UsuariosClientError> {
        let http = Client::builder()
            .build()
            .map_err(|_| UsuariosClientError::RequestBuild)?;

        Ok(Self {
            http,
            base_url,
            shared_secret,
        })
    }

    /// Obtiene el perfil de `identity` desde `ms-usuarios` (`GET /users/me`).
    ///
    /// Falla con [`UsuariosClientError::Unreachable`] si no se pudo contactar
    /// al servicio, con [`UsuariosClientError::UnexpectedResponse`] si
    /// respondió un status no-2xx (incluida una credencial de servicio
    /// rechazada con 401, o cualquier 5xx), y con
    /// [`UsuariosClientError::MalformedResponse`] si el cuerpo 2xx no es JSON
    /// válido. Nunca entra en pánico.
    pub async fn get_profile(
        &self,
        identity: &Session,
    ) -> Result<UserProfile, UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .get(self.profile_url())
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            );

        self.send_and_decode(request).await
    }

    /// Crea o reemplaza el perfil de `identity` en `ms-usuarios`
    /// (`PUT /users/me`), reenviando `profile` tal cual (ver la nota de
    /// diseño al inicio de este módulo).
    ///
    /// Mismos errores que [`Self::get_profile`].
    pub async fn upsert_profile(
        &self,
        identity: &Session,
        profile: &UserProfile,
    ) -> Result<UserProfile, UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .put(self.profile_url())
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            )
            .json(profile);

        self.send_and_decode(request).await
    }

    fn profile_url(&self) -> String {
        format!("{}/users/me", self.base_url.trim_end_matches('/'))
    }

    fn identity_header_value(&self, identity: &Session) -> Result<String, UsuariosClientError> {
        serde_json::to_string(&IdentityHeaderPayload {
            sub: &identity.sub,
            email: &identity.email,
        })
        .map_err(|_| UsuariosClientError::RequestBuild)
    }

    async fn send_and_decode(
        &self,
        request: RequestBuilder,
    ) -> Result<UserProfile, UsuariosClientError> {
        let response = request
            .send()
            .await
            .map_err(|_| UsuariosClientError::Unreachable)?;

        let status = response.status();
        if !status.is_success() {
            return Err(UsuariosClientError::UnexpectedResponse {
                status: status.as_u16(),
            });
        }

        response
            .json::<UserProfile>()
            .await
            .map_err(|_| UsuariosClientError::MalformedResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab_client() -> UsuariosClient {
        UsuariosClient::new(
            "http://ms-usuarios.internal".to_string(),
            SecretString::from("lab-only-not-a-real-secret".to_string()),
        )
        .expect("cliente de laboratorio debe construirse")
    }

    #[test]
    fn profile_url_joins_base_url_without_double_slash() {
        let client = UsuariosClient::new(
            "http://ms-usuarios.internal/".to_string(),
            SecretString::from("lab-only-not-a-real-secret".to_string()),
        )
        .expect("cliente de laboratorio debe construirse");

        assert_eq!(client.profile_url(), "http://ms-usuarios.internal/users/me");
    }

    #[test]
    fn identity_header_value_encodes_sub_and_email() {
        let client = lab_client();
        let identity = Session {
            sub: "google-sub-123".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            exp: 9_999_999_999,
        };

        let value = client
            .identity_header_value(&identity)
            .expect("debe poder serializar la identidad");

        let decoded: serde_json::Value = serde_json::from_str(&value).expect("JSON válido");
        assert_eq!(decoded["sub"], "google-sub-123");
        assert_eq!(decoded["email"], "user@example.com");
        assert!(
            decoded.get("name").is_none(),
            "el header de identidad no debe reenviar el nombre, solo sub/email"
        );
    }

    #[test]
    fn error_messages_never_include_the_base_url() {
        let client = UsuariosClient::new(
            "http://ms-usuarios.internal:9999".to_string(),
            SecretString::from("lab-only-not-a-real-secret".to_string()),
        )
        .expect("cliente de laboratorio debe construirse");
        let _ = client; // la URL solo se usa para construir el cliente, no aparece abajo

        for error in [
            UsuariosClientError::Unreachable,
            UsuariosClientError::UnexpectedResponse { status: 500 },
            UsuariosClientError::MalformedResponse,
            UsuariosClientError::RequestBuild,
        ] {
            let message = error.to_string();
            assert!(!message.contains("ms-usuarios.internal"));
        }
    }
}
