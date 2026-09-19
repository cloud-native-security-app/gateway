//! Tipos de dominio puros (sin IO): sesión verificada, envío de escaneo,
//! eventos de estado de un escaneo.

use serde::{Deserialize, Serialize};

/// Identidad de un usuario ya autenticado por Google y verificada por este
/// Gateway (firma/`aud`/`iss`/`exp` del ID token, ver `docs/security-scope.md`),
/// junto con la validez temporal de la sesión propia que la encapsula
/// (RNF-02).
///
/// No contiene ningún dato crudo de Google (el ID token se descarta tras
/// extraer esta identidad) ni el `aud`/`iss` propios del JWT de sesión, que
/// son un detalle de codificación de `auth` y no de este tipo de dominio
/// puro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Identificador estable del usuario en Google (`sub`).
    pub sub: String,
    /// Correo electrónico del usuario, tal como lo reporta Google.
    pub email: String,
    /// Nombre para mostrar del usuario, tal como lo reporta Google (cadena
    /// vacía si Google no lo incluyó en el ID token).
    pub name: String,
    /// Momento de expiración de la sesión propia, en segundos desde el
    /// epoch Unix.
    pub exp: u64,
}
