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

/// Evento de avance de un escaneo publicado por `ms-nmap` en
/// `gateway.scan-outcomes` (routing keys `scan.outcome.started`/`completed`/
/// `failed`), consumido por este Gateway (feature `scan_outcome_relay`) y
/// relayado a los clientes SSE suscritos al `scanId` correspondiente
/// (RF-07/RF-08).
///
/// Shape copiado literalmente de `broker/contracts/scan-outcome.schema.json`
/// (`oneOf` discriminado por `status`, `additionalProperties: false` en cada
/// variante — de ahí `#[serde(deny_unknown_fields)]`): un mensaje que no
/// respeta este contrato falla al deserializar, lo cual el consumidor de
/// `crate::broker` trata como mensaje malformado (se descarta, nunca tumba
/// el proceso).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScanOutcomeEvent {
    /// El escaneo comenzó a ejecutarse (`ms-nmap` lo refleja como
    /// `EnProgreso` en `ms-usuarios`). Contrato acordado, aunque `ms-nmap`
    /// todavía no lo publica en producción (ver
    /// `broker/contracts/README.md`) — este consumidor lo trata igual que
    /// las otras dos variantes.
    Started {
        /// Identificador de correlación: el `scanId` propio de este
        /// Gateway, el mismo que generó `POST /api/scans` (feature
        /// `scan_submission`) y usó como `correlation_id` del `ScanRequest`
        /// publicado.
        correlation_id: String,
    },
    /// El escaneo terminó exitosamente, con un resultado utilizable.
    Completed {
        /// Ver [`Self::Started`].
        correlation_id: String,
        /// Resultado completo del escaneo (puertos, hallazgos de
        /// vulnerabilidades).
        result: ScanResult,
    },
    /// El escaneo terminó con un error y no produjo un resultado
    /// utilizable.
    Failed {
        /// Ver [`Self::Started`].
        correlation_id: String,
        /// Motivo del fallo, tal como lo reporta `ms-nmap`.
        reason: String,
    },
}

impl ScanOutcomeEvent {
    /// Identificador de correlación de este evento: el `scanId` propio de
    /// este Gateway (ver [`Self::Started::correlation_id`]), común a las
    /// tres variantes.
    pub fn correlation_id(&self) -> &str {
        match self {
            ScanOutcomeEvent::Started { correlation_id }
            | ScanOutcomeEvent::Completed { correlation_id, .. }
            | ScanOutcomeEvent::Failed { correlation_id, .. } => correlation_id,
        }
    }

    /// `true` si este evento representa un estado terminal (`completed`/
    /// `failed`): un stream SSE debe cerrarse ordenadamente justo después de
    /// emitirlo (ver `crate::realtime`).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ScanOutcomeEvent::Completed { .. } | ScanOutcomeEvent::Failed { .. }
        )
    }
}

/// Resultado completo de un escaneo (`ScanOutcomeEvent::Completed::result`).
/// Shape copiado literalmente de `broker/contracts/scan-outcome.schema.json`
/// (`$defs/scanResult`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanResult {
    /// IP escaneada.
    pub host: String,
    /// Puertos encontrados y su estado.
    pub ports: Vec<PortFinding>,
    /// Hallazgos de vulnerabilidades asociados al escaneo.
    pub vulnerabilities: Vec<VulnFinding>,
    /// Marca de tiempo (RFC 3339) en la que se completó el escaneo, tal
    /// cual la reporta `ms-nmap`. No se interpreta como fecha/hora en este
    /// Gateway (se reenvía tal cual a `front` vía SSE).
    pub scanned_at: String,
}

/// Hallazgo de un puerto individual dentro de un [`ScanResult`]. Shape
/// copiado de `broker/contracts/scan-outcome.schema.json`
/// (`$defs/portFinding`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortFinding {
    /// Número de puerto (0-65535).
    pub port: u16,
    /// Protocolo de transporte (`tcp`/`udp`, tal como lo reporta
    /// `ms-nmap`).
    pub protocol: String,
    /// Estado del puerto (`open`/`closed`/`filtered`/..., tal como lo
    /// reporta `ms-nmap`).
    pub state: String,
    /// Servicio detectado en el puerto, si `ms-nmap` pudo identificarlo.
    pub service: Option<String>,
    /// Versión del servicio detectado, si `ms-nmap` pudo identificarla.
    pub version: Option<String>,
    /// Identificadores CPE asociados al servicio detectado.
    pub cpes: Vec<String>,
}

/// Hallazgo de una vulnerabilidad individual dentro de un [`ScanResult`].
/// Shape copiado de `broker/contracts/scan-outcome.schema.json`
/// (`$defs/vulnFinding`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnFinding {
    /// Identificador de la vulnerabilidad (p. ej. CVE), si se conoce.
    pub id: Option<String>,
    /// Severidad reportada (`unknown`/`info`/`low`/`medium`/`high`/
    /// `critical`).
    pub severity: String,
    /// Descripción de la vulnerabilidad.
    pub description: String,
    /// Script NSE de `nmap` que detectó el hallazgo (cadena vacía si no
    /// aplica).
    pub nse_script: String,
    /// Origen del hallazgo (`nmap_nse`/`exploit_db`/`nvd`).
    pub source: String,
    /// Referencias externas asociadas al hallazgo.
    pub references: Vec<String>,
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

    #[test]
    fn scan_outcome_event_decodes_started_variant() {
        let json = serde_json::json!({
            "status": "started",
            "correlation_id": "scan-1",
        });

        let event: ScanOutcomeEvent =
            serde_json::from_value(json).expect("started debe decodificar");

        assert_eq!(event.correlation_id(), "scan-1");
        assert!(!event.is_terminal());
        assert!(matches!(event, ScanOutcomeEvent::Started { .. }));
    }

    #[test]
    fn scan_outcome_event_decodes_completed_variant_with_full_result() {
        let json = serde_json::json!({
            "status": "completed",
            "correlation_id": "scan-2",
            "result": {
                "host": "192.0.2.10",
                "ports": [{
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "version": null,
                    "cpes": [],
                }],
                "vulnerabilities": [{
                    "id": "CVE-2024-0001",
                    "severity": "high",
                    "description": "algo",
                    "nse_script": "",
                    "source": "nvd",
                    "references": [],
                }],
                "scanned_at": "2024-01-01T00:00:00Z",
            },
        });

        let event: ScanOutcomeEvent =
            serde_json::from_value(json).expect("completed debe decodificar");

        assert_eq!(event.correlation_id(), "scan-2");
        assert!(event.is_terminal());
        assert!(matches!(event, ScanOutcomeEvent::Completed { .. }));
    }

    #[test]
    fn scan_outcome_event_decodes_failed_variant() {
        let json = serde_json::json!({
            "status": "failed",
            "correlation_id": "scan-3",
            "reason": "host inalcanzable",
        });

        let event: ScanOutcomeEvent =
            serde_json::from_value(json).expect("failed debe decodificar");

        assert_eq!(event.correlation_id(), "scan-3");
        assert!(event.is_terminal());
    }

    #[test]
    fn scan_outcome_event_rejects_unknown_status() {
        let json = serde_json::json!({
            "status": "progressing",
            "correlation_id": "scan-4",
        });

        assert!(serde_json::from_value::<ScanOutcomeEvent>(json).is_err());
    }

    #[test]
    fn scan_outcome_event_rejects_extra_fields() {
        let json = serde_json::json!({
            "status": "started",
            "correlation_id": "scan-5",
            "unexpected": "field",
        });

        assert!(serde_json::from_value::<ScanOutcomeEvent>(json).is_err());
    }

    #[test]
    fn scan_outcome_event_rejects_missing_required_field() {
        let json = serde_json::json!({
            "status": "failed",
            "correlation_id": "scan-6",
        });

        assert!(serde_json::from_value::<ScanOutcomeEvent>(json).is_err());
    }
}
