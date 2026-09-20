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
//!
//! ## Histórico de escaneos (feature `scan_submission`)
//!
//! [`UsuariosClient::create_scan_history`] (`POST /users/me/scans`),
//! [`UsuariosClient::list_scan_history`] (`GET /users/me/scans`, misma ruta
//! de colección que `create_scan_history`, distinto verbo HTTP — feature
//! `scan_history_and_cancellation`) y [`UsuariosClient::update_scan_status`]
//! (`PATCH /scans/{scan_id}`) están confirmados contra el contrato real de
//! `user-service` (`user-service/src/api.rs`, y `user-service/src/domain.rs`
//! para [`ScanStatus`]/[`ScanHistoryEntry`]).
//!
//! [`UsuariosClient::resolve_scan_target`] es distinto: llama a un endpoint
//! **especulativo**, `GET /users/me/scan-targets?target=<ip-o-cidr>`, que
//! **no existe todavía** en `user-service` (ver `docs/architecture.md`
//! §"Dependencia pendiente" y `docs/security-scope.md`
//! §"Origen de `network_user`/`ssh_credentials_ref`/`has_sudo`"). El nombre
//! de ruta y el shape de su respuesta (`network_user`/`ssh_credentials_ref`/
//! `has_sudo`) son una suposición documentada de este repo, a confirmar
//! contra el contrato real cuando `user-service` implemente esa API — nunca
//! se trata su resultado como si estuviera confirmado. Un `404` de
//! `ms-usuarios` (la API no existe) y un `422` (API existe pero sin
//! credenciales configuradas para este usuario/objetivo) se distinguen
//! explícitamente en [`UsuariosClientError`], y ninguno de los dos casos
//! produce jamás un valor inventado en su lugar.

use reqwest::{Client, RequestBuilder, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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

/// Estado de una solicitud de escaneo en el histórico de `ms-usuarios`.
///
/// Codificación (`SCREAMING_SNAKE_CASE`) confirmada contra
/// `user-service/src/domain.rs::ScanStatus`
/// (`#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`), no una suposición de
/// este repo.
///
/// `ToSchema` (feature `openapi_docs`, RNF-08): este tipo aparece como campo
/// de `GET /api/scans` en la especificación OpenAPI generada (ver
/// `crate::api::ScanHistoryEntryResponse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    /// El escaneo fue solicitado pero aún no ha comenzado a ejecutarse.
    Pendiente,
    /// El escaneo está siendo ejecutado actualmente.
    EnProgreso,
    /// El escaneo terminó exitosamente.
    Completado,
    /// El escaneo terminó con un error y no produjo un resultado utilizable.
    Fallido,
}

/// Entrada del histórico de escaneos de `ms-usuarios`, tal como la devuelve
/// `POST /users/me/scans`. Shape confirmado contra
/// `user-service/src/domain.rs::ScanHistoryEntry`. `requested_at`/
/// `updated_at` se conservan como el `String` (RFC 3339) tal cual los
/// serializa `ms-usuarios`: este cliente no los interpreta como fecha/hora,
/// así que no hace falta una dependencia de manejo de tiempo solo para
/// transportarlos.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanHistoryEntry {
    /// Identificador único de la solicitud de escaneo, asignado por
    /// `ms-usuarios` (no por este Gateway).
    pub scan_id: String,
    /// Identidad del usuario que solicitó el escaneo.
    pub user_id: String,
    /// Objetivo del escaneo (IP o rango, tal como se envió).
    pub target: String,
    /// Estado actual de la entrada.
    pub status: ScanStatus,
    /// Marca de tiempo (RFC 3339) en la que se solicitó el escaneo.
    pub requested_at: String,
    /// Marca de tiempo (RFC 3339) de la última actualización de estado.
    pub updated_at: String,
}

/// Credenciales de red resueltas por `ms-usuarios` para un objetivo de
/// escaneo, vía el endpoint especulativo que documenta
/// [`UsuariosClient::resolve_scan_target`].
///
/// `ssh_credentials_ref` transporta una credencial SSH **real** (ver
/// `docs/security-scope.md`): este tipo implementa `Debug` a mano para
/// redactarla, en vez de derivarlo.
#[derive(Clone, Deserialize)]
pub struct ScanTargetCredentials {
    /// Usuario de red a usar para autenticarse en el objetivo.
    pub network_user: String,
    /// Credencial SSH real para autenticarse en el objetivo. Nunca se
    /// loggea.
    pub ssh_credentials_ref: String,
    /// Si `network_user` tiene privilegios `sudo` en el objetivo.
    pub has_sudo: bool,
}

impl std::fmt::Debug for ScanTargetCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanTargetCredentials")
            .field("network_user", &self.network_user)
            .field("ssh_credentials_ref", &"[REDACTED]")
            .field("has_sudo", &self.has_sudo)
            .finish()
    }
}

/// Cuerpo de `POST /users/me/scans`.
#[derive(Debug, Serialize)]
struct CreateScanHistoryRequest<'a> {
    target: &'a str,
}

/// Cuerpo de `PATCH /scans/{scan_id}`.
#[derive(Debug, Serialize)]
struct UpdateScanStatusRequest {
    status: ScanStatus,
}

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
    /// La API de `ms-usuarios` para resolver `network_user`/
    /// `ssh_credentials_ref`/`has_sudo` de un objetivo de escaneo todavía no
    /// existe (`404`) — ver `docs/architecture.md` §"Dependencia pendiente".
    /// Nunca se sustituye por un valor inventado.
    #[error(
        "la API de ms-usuarios para resolver las credenciales de red de este escaneo todavía no existe"
    )]
    ScanTargetResolutionNotImplemented,
    /// `ms-usuarios` respondió que no hay credenciales de red configuradas
    /// para este usuario/objetivo (`422`).
    #[error("no hay credenciales de red configuradas para este usuario y objetivo")]
    ScanTargetNotConfigured,
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

    /// Registra una nueva entrada de histórico para `target` a nombre de
    /// `identity` (`POST /users/me/scans`, estado inicial `Pendiente` del
    /// lado de `ms-usuarios`).
    ///
    /// El `scan_id` de la entrada devuelta lo asigna `ms-usuarios`, no este
    /// Gateway (el contrato real de `POST /users/me/scans` no acepta un
    /// identificador externo) — es ese `scan_id`, y no el `correlation_id`
    /// propio que este Gateway ya generó para el `ScanRequest` del Broker,
    /// el que debe usarse en una llamada posterior a
    /// [`Self::update_scan_status`] para esta misma entrada.
    ///
    /// Mismos errores que [`Self::get_profile`].
    pub async fn create_scan_history(
        &self,
        identity: &Session,
        target: &str,
    ) -> Result<ScanHistoryEntry, UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .post(self.scans_url())
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            )
            .json(&CreateScanHistoryRequest { target });

        self.send_and_decode(request).await
    }

    /// Devuelve el histórico completo de escaneos de `identity`
    /// (`GET /users/me/scans`, feature `scan_history_and_cancellation`, RF-13):
    /// la autorización a nivel de fila (un usuario solo ve su propio
    /// histórico) la aplica `ms-usuarios` a partir del header de identidad ya
    /// verificada, este cliente no la reimplementa (ver
    /// `docs/security-scope.md`).
    ///
    /// Mismos errores que [`Self::get_profile`].
    pub async fn list_scan_history(
        &self,
        identity: &Session,
    ) -> Result<Vec<ScanHistoryEntry>, UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .get(self.scans_url())
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            );

        self.send_and_decode(request).await
    }

    /// Actualiza el estado de la entrada de histórico `scan_id` (el
    /// asignado por `ms-usuarios`, ver [`Self::create_scan_history`]) a
    /// `status` (`PATCH /scans/{scan_id}`, `204 No Content` en éxito).
    ///
    /// Mismos errores que [`Self::get_profile`] (un `scan_id` inexistente o
    /// de otro usuario se refleja como
    /// [`UsuariosClientError::UnexpectedResponse`] con el `404`/`403` real
    /// de `ms-usuarios`).
    pub async fn update_scan_status(
        &self,
        identity: &Session,
        scan_id: &str,
        status: ScanStatus,
    ) -> Result<(), UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .patch(self.scan_status_url(scan_id))
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            )
            .json(&UpdateScanStatusRequest { status });

        let response = request
            .send()
            .await
            .map_err(|_| UsuariosClientError::Unreachable)?;

        let status_code = response.status();
        if !status_code.is_success() {
            return Err(UsuariosClientError::UnexpectedResponse {
                status: status_code.as_u16(),
            });
        }

        Ok(())
    }

    /// Intenta resolver `network_user`/`ssh_credentials_ref`/`has_sudo` para
    /// `target` a nombre de `identity`, contra el endpoint **especulativo**
    /// `GET /users/me/scan-targets?target=<target>` (ver la nota de diseño
    /// al inicio de este módulo: esa API todavía no existe en
    /// `user-service`).
    ///
    /// Falla con [`UsuariosClientError::ScanTargetResolutionNotImplemented`]
    /// si `ms-usuarios` respondió `404` (la API no existe todavía), con
    /// [`UsuariosClientError::ScanTargetNotConfigured`] si respondió `422`
    /// (la API existe pero no hay credenciales configuradas para este
    /// usuario/objetivo), y con el resto de variantes de
    /// [`UsuariosClientError`] en los mismos casos que [`Self::get_profile`]
    /// para cualquier otra respuesta. Nunca devuelve un valor inventado en
    /// lugar de un error.
    pub async fn resolve_scan_target(
        &self,
        identity: &Session,
        target: &str,
    ) -> Result<ScanTargetCredentials, UsuariosClientError> {
        let identity_header = self.identity_header_value(identity)?;
        let request = self
            .http
            .get(self.scan_targets_url())
            .query(&[("target", target)])
            .header(FORWARDED_USER_HEADER_NAME, identity_header)
            .header(
                GATEWAY_SECRET_HEADER_NAME,
                self.shared_secret.expose_secret(),
            );

        let response = request
            .send()
            .await
            .map_err(|_| UsuariosClientError::Unreachable)?;

        match response.status() {
            status if status.is_success() => response
                .json::<ScanTargetCredentials>()
                .await
                .map_err(|_| UsuariosClientError::MalformedResponse),
            StatusCode::NOT_FOUND => Err(UsuariosClientError::ScanTargetResolutionNotImplemented),
            StatusCode::UNPROCESSABLE_ENTITY => Err(UsuariosClientError::ScanTargetNotConfigured),
            other => Err(UsuariosClientError::UnexpectedResponse {
                status: other.as_u16(),
            }),
        }
    }

    fn profile_url(&self) -> String {
        format!("{}/users/me", self.base_url.trim_end_matches('/'))
    }

    fn scans_url(&self) -> String {
        format!("{}/users/me/scans", self.base_url.trim_end_matches('/'))
    }

    fn scan_status_url(&self, scan_id: &str) -> String {
        format!("{}/scans/{scan_id}", self.base_url.trim_end_matches('/'))
    }

    /// URL del endpoint especulativo que consulta
    /// [`Self::resolve_scan_target`] — ver la nota de diseño al inicio de
    /// este módulo.
    fn scan_targets_url(&self) -> String {
        format!(
            "{}/users/me/scan-targets",
            self.base_url.trim_end_matches('/')
        )
    }

    fn identity_header_value(&self, identity: &Session) -> Result<String, UsuariosClientError> {
        serde_json::to_string(&IdentityHeaderPayload {
            sub: &identity.sub,
            email: &identity.email,
        })
        .map_err(|_| UsuariosClientError::RequestBuild)
    }

    async fn send_and_decode<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, UsuariosClientError> {
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
            .json::<T>()
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
            UsuariosClientError::ScanTargetResolutionNotImplemented,
            UsuariosClientError::ScanTargetNotConfigured,
        ] {
            let message = error.to_string();
            assert!(!message.contains("ms-usuarios.internal"));
        }
    }

    #[test]
    fn scans_url_joins_base_url_without_double_slash() {
        let client = UsuariosClient::new(
            "http://ms-usuarios.internal/".to_string(),
            SecretString::from("lab-only-not-a-real-secret".to_string()),
        )
        .expect("cliente de laboratorio debe construirse");

        assert_eq!(
            client.scans_url(),
            "http://ms-usuarios.internal/users/me/scans"
        );
    }

    #[test]
    fn scan_status_url_includes_the_given_scan_id() {
        let client = lab_client();

        assert_eq!(
            client.scan_status_url("scan-123"),
            "http://ms-usuarios.internal/scans/scan-123"
        );
    }

    #[test]
    fn scan_targets_url_points_to_the_speculative_endpoint() {
        let client = lab_client();

        assert_eq!(
            client.scan_targets_url(),
            "http://ms-usuarios.internal/users/me/scan-targets"
        );
    }

    #[test]
    fn scan_status_serializes_as_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&ScanStatus::Pendiente).unwrap(),
            "\"PENDIENTE\""
        );
        assert_eq!(
            serde_json::to_string(&ScanStatus::Fallido).unwrap(),
            "\"FALLIDO\""
        );
    }

    #[test]
    fn scan_history_entry_deserializes_the_real_contract_shape() {
        let json = serde_json::json!({
            "scan_id": "scan-1",
            "user_id": "google-sub-123",
            "target": "192.0.2.10",
            "status": "PENDIENTE",
            "requested_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        });

        let entry: ScanHistoryEntry =
            serde_json::from_value(json).expect("debe deserializar el contrato real");

        assert_eq!(entry.scan_id, "scan-1");
        assert_eq!(entry.status, ScanStatus::Pendiente);
    }

    #[test]
    fn scan_target_credentials_debug_redacts_ssh_credentials_ref() {
        let credentials = ScanTargetCredentials {
            network_user: "netuser".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
        };

        let debug_output = format!("{credentials:?}");

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(debug_output.contains("REDACTED"));
    }
}
