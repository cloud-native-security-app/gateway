//! Tipos de dominio puros (sin IO): sesión verificada, envío de escaneo,
//! eventos de estado de un escaneo.

use std::net::IpAddr;

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

/// Errores al validar el objetivo (`target`) de una solicitud de escaneo
/// (RF-02/RF-03), lógica pura sin ningún acceso a `ms-usuarios` ni al
/// Broker.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanSubmissionError {
    /// El campo `target` llegó vacío (o solo espacios en blanco).
    #[error("el objetivo del escaneo no puede estar vacío")]
    EmptyTarget,
    /// `target` no es ni una IP (IPv4/IPv6) ni un rango CIDR válido.
    #[error("'{target}' no es una IP ni un rango CIDR válido")]
    InvalidTarget {
        /// Valor recibido que no superó la validación.
        target: String,
    },
}

/// Entrada validada de una solicitud de escaneo: una IP o rango CIDR con
/// formato correcto (RF-02/RF-03), previa a cualquier resolución contra
/// `ms-usuarios` o publicación en el Broker.
///
/// Construirlo (vía [`ScanSubmission::parse`]) es la única forma de obtener
/// un `target` ya validado: no hay ningún constructor que se salte esa
/// validación, para que ninguna llamada externa (RF-04) pueda alcanzarse
/// con un formato inválido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSubmission {
    /// IP (IPv4/IPv6) o rango CIDR objetivo del escaneo, ya validado.
    pub target: String,
}

impl ScanSubmission {
    /// Valida `raw_target` como una IP (IPv4/IPv6) o un rango CIDR
    /// (`<ip>/<prefijo>`, con el prefijo dentro del rango válido para esa
    /// familia de dirección).
    ///
    /// Falla con [`ScanSubmissionError::EmptyTarget`] si `raw_target` está
    /// vacío tras recortar espacios, o con
    /// [`ScanSubmissionError::InvalidTarget`] si no es una IP ni un CIDR
    /// válido. No hace ninguna llamada externa ni valida nada más allá del
    /// formato (p. ej. no comprueba que la IP sea alcanzable).
    pub fn parse(raw_target: &str) -> Result<Self, ScanSubmissionError> {
        let target = raw_target.trim();
        if target.is_empty() {
            return Err(ScanSubmissionError::EmptyTarget);
        }

        let is_valid = match target.split_once('/') {
            Some((ip_part, prefix_part)) => is_valid_cidr(ip_part, prefix_part),
            None => target.parse::<IpAddr>().is_ok(),
        };

        if !is_valid {
            return Err(ScanSubmissionError::InvalidTarget {
                target: target.to_string(),
            });
        }

        Ok(Self {
            target: target.to_string(),
        })
    }
}

/// Valida que `ip_part` sea una IP y `prefix_part` un prefijo de red válido
/// para su familia (0-32 para IPv4, 0-128 para IPv6).
fn is_valid_cidr(ip_part: &str, prefix_part: &str) -> bool {
    let Ok(ip) = ip_part.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    prefix <= max_prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_ipv4_address() {
        let submission = ScanSubmission::parse("192.0.2.10").expect("IPv4 válida debe parsear");
        assert_eq!(submission.target, "192.0.2.10");
    }

    #[test]
    fn parses_a_valid_ipv6_address() {
        let submission = ScanSubmission::parse("2001:db8::1").expect("IPv6 válida debe parsear");
        assert_eq!(submission.target, "2001:db8::1");
    }

    #[test]
    fn parses_a_valid_ipv4_cidr_range() {
        let submission =
            ScanSubmission::parse("10.0.0.0/24").expect("rango CIDR IPv4 válido debe parsear");
        assert_eq!(submission.target, "10.0.0.0/24");
    }

    #[test]
    fn parses_a_valid_ipv6_cidr_range() {
        let submission =
            ScanSubmission::parse("2001:db8::/32").expect("rango CIDR IPv6 válido debe parsear");
        assert_eq!(submission.target, "2001:db8::/32");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let submission = ScanSubmission::parse("  192.0.2.10  ").expect("debe recortar espacios");
        assert_eq!(submission.target, "192.0.2.10");
    }

    #[test]
    fn rejects_empty_target() {
        assert_eq!(
            ScanSubmission::parse("   "),
            Err(ScanSubmissionError::EmptyTarget)
        );
    }

    #[test]
    fn rejects_garbage_that_is_neither_ip_nor_cidr() {
        assert_eq!(
            ScanSubmission::parse("not-an-ip"),
            Err(ScanSubmissionError::InvalidTarget {
                target: "not-an-ip".to_string()
            })
        );
    }

    #[test]
    fn rejects_ipv4_cidr_with_prefix_out_of_range() {
        assert_eq!(
            ScanSubmission::parse("10.0.0.0/33"),
            Err(ScanSubmissionError::InvalidTarget {
                target: "10.0.0.0/33".to_string()
            })
        );
    }

    #[test]
    fn rejects_cidr_with_non_numeric_prefix() {
        assert!(ScanSubmission::parse("10.0.0.0/abc").is_err());
    }
}
