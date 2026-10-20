//! Carga y validación de la configuración del servicio desde variables de
//! entorno (feature `config`).

use std::env;
use std::num::ParseIntError;

use secrecy::SecretString;

/// Nombre de la variable de entorno con el host donde escucha el servidor
/// HTTP de este Gateway.
const ENV_HTTP_HOST: &str = "HTTP_HOST";
/// Nombre de la variable de entorno con el puerto donde escucha el servidor
/// HTTP de este Gateway.
const ENV_HTTP_PORT: &str = "HTTP_PORT";
/// Nombre de la variable de entorno con el `client_id` OAuth de Google.
const ENV_GOOGLE_CLIENT_ID: &str = "GOOGLE_CLIENT_ID";
/// Nombre de la variable de entorno con el `client_secret` OAuth de Google.
const ENV_GOOGLE_CLIENT_SECRET: &str = "GOOGLE_CLIENT_SECRET";
/// Nombre de la variable de entorno con la URI de redirección registrada
/// ante Google para el callback OIDC.
const ENV_GOOGLE_REDIRECT_URI: &str = "GOOGLE_REDIRECT_URI";
/// Nombre de la variable de entorno con la URL de discovery/issuer OIDC
/// contra la que este Gateway hace el handshake (Google en producción, un
/// IdP de prueba en tests de integración). Opcional: si no se define, se usa
/// [`DEFAULT_GOOGLE_OIDC_ISSUER_URL`].
const ENV_GOOGLE_OIDC_ISSUER_URL: &str = "GOOGLE_OIDC_ISSUER_URL";
/// Valor por defecto de `GOOGLE_OIDC_ISSUER_URL` cuando no se define: el
/// issuer real de Google en producción.
const DEFAULT_GOOGLE_OIDC_ISSUER_URL: &str = "https://accounts.google.com";
/// Nombre de la variable de entorno con la clave de firma de la sesión
/// propia de este Gateway.
const ENV_SESSION_SIGNING_KEY: &str = "SESSION_SIGNING_KEY";
/// Nombre de la variable de entorno con el tiempo de vida (en segundos) de
/// la sesión propia de este Gateway.
const ENV_SESSION_TTL_SECS: &str = "SESSION_TTL_SECS";
/// Nombre de la variable de entorno con la URL fija de `front` a la que
/// `GET /auth/callback` redirige (`302`) tras completar el login (feature
/// `post_login_redirect`). Nunca se deriva de la query string de la request
/// original: fijarla en configuración evita un open redirect.
const ENV_FRONT_BASE_URL: &str = "FRONT_BASE_URL";
/// Nombre de la variable de entorno con la URL base de `ms-usuarios`.
const ENV_MS_USUARIOS_BASE_URL: &str = "MS_USUARIOS_BASE_URL";
/// Nombre de la variable de entorno con la credencial de servicio
/// compartida con `ms-usuarios`.
const ENV_MS_USUARIOS_SHARED_SECRET: &str = "MS_USUARIOS_SHARED_SECRET";
/// Nombre de la variable de entorno con el número máximo de solicitudes de
/// `POST /api/scans` que un mismo usuario (identidad de la sesión, no IP,
/// ver `docs/security-scope.md`) puede hacer dentro de una ventana de
/// [`ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS`] (RF-12).
const ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS: &str = "SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS";
/// Nombre de la variable de entorno con la duración (en segundos) de la
/// ventana de tiempo sobre la que se cuenta
/// [`ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS`] (RF-12).
const ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS: &str = "SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS";
/// Nombre de la variable de entorno con la región de AWS usada por los
/// clientes SNS/SQS. Requerida y no vacía.
const ENV_AWS_REGION: &str = "AWS_REGION";
/// Nombre de la variable de entorno con el endpoint alternativo de AWS
/// (solo LocalStack). Opcional: si no se define, se usa el endpoint real de
/// AWS.
const ENV_AWS_ENDPOINT_URL: &str = "AWS_ENDPOINT_URL";
/// Nombre de la variable de entorno con el ARN del topic SNS de solicitudes
/// de escaneo.
const ENV_SCAN_REQUESTS_TOPIC_ARN: &str = "SCAN_REQUESTS_TOPIC_ARN";
/// Nombre de la variable de entorno con el ARN del topic SNS de
/// cancelaciones de escaneo.
const ENV_SCAN_CANCELLATIONS_TOPIC_ARN: &str = "SCAN_CANCELLATIONS_TOPIC_ARN";
/// Nombre de la variable de entorno con la URL de la cola SQS de resultados
/// de escaneo que consume este Gateway.
const ENV_SCAN_OUTCOMES_QUEUE_URL: &str = "GATEWAY_SCAN_OUTCOMES_QUEUE_URL";
/// Nombre de la variable de entorno con la URL de la dead-letter queue SQS
/// asociada a la cola de resultados de escaneo.
const ENV_SCAN_OUTCOMES_DLQ_URL: &str = "GATEWAY_SCAN_OUTCOMES_DLQ_URL";

/// Configuración completa del servicio, cargada desde variables de entorno.
///
/// Ningún valor aquí está hardcodeado en el código: todos provienen de
/// [`Config::from_env`]. Los campos que transportan una credencial usan
/// [`SecretString`], que redacta su contenido en `Debug` y no implementa
/// `Display`, de modo que no puede filtrarse por accidente en un log o un
/// mensaje de error (ver `docs/security-scope.md`).
#[derive(Debug)]
pub struct Config {
    /// Host en el que este Gateway expone su servidor HTTP.
    pub http_host: String,
    /// Puerto en el que este Gateway expone su servidor HTTP.
    pub http_port: u16,
    /// `client_id` OAuth de Google (RF-01).
    pub google_client_id: String,
    /// `client_secret` OAuth de Google (RF-01). Nunca se loggea.
    pub google_client_secret: SecretString,
    /// URI de redirección registrada ante Google para el callback OIDC.
    pub google_redirect_uri: String,
    /// URL de discovery/issuer OIDC contra la que este Gateway hace el
    /// handshake (Google en producción, un IdP de prueba en tests). Nunca
    /// hardcodeada en el código: permite apuntar a un servidor distinto sin
    /// recompilar.
    pub google_oidc_issuer_url: String,
    /// Clave de firma de la sesión propia de este Gateway (`jsonwebtoken`).
    /// Nunca se loggea.
    pub session_signing_key: SecretString,
    /// Tiempo de vida, en segundos, de la sesión propia de este Gateway.
    pub session_ttl_secs: u64,
    /// URL fija de `front` a la que `GET /auth/callback` redirige (`302`)
    /// tras completar el login. Nunca se deriva de la request original (ver
    /// `docs/security-scope.md`: evita un open redirect).
    pub front_base_url: String,
    /// Origen (`scheme://host[:puerto]`, sin `path`) derivado de
    /// [`Config::front_base_url`] — no es una variable de entorno nueva,
    /// sino el mismo valor de `FRONT_BASE_URL` normalizado a la forma que
    /// compara el header `Origin` de una request CORS (RFC 6454): ese
    /// header nunca lleva `path`, así que no basta con reflejar el string
    /// crudo de `front_base_url` (que sí puede llevarlo, p. ej.
    /// `https://front.example/post-login`). Único origen permitido por la
    /// `CorsLayer` de este Gateway (feature `cors_for_front`) — nunca un
    /// wildcard (ver `docs/security-scope.md`).
    pub front_origin: String,
    /// URL base de `ms-usuarios`, nunca expuesta a `front`.
    pub ms_usuarios_base_url: String,
    /// Credencial de servicio compartida con `ms-usuarios`. Nunca se
    /// loggea.
    pub ms_usuarios_shared_secret: SecretString,
    /// Número máximo de solicitudes de `POST /api/scans` que un mismo
    /// usuario puede hacer dentro de
    /// [`Config::scan_submission_rate_limit_window_secs`] (RF-12, feature
    /// `rate_limiting`). Sin valor hardcodeado en el código.
    pub scan_submission_rate_limit_max_requests: u32,
    /// Duración, en segundos, de la ventana de tiempo sobre la que se cuenta
    /// [`Config::scan_submission_rate_limit_max_requests`].
    pub scan_submission_rate_limit_window_secs: u64,
    /// Región de AWS usada por los clientes SNS/SQS. Las credenciales nunca
    /// se configuran aquí: vienen de la cadena de proveedores por defecto de
    /// AWS (rol de la tarea ECS).
    pub aws_region: String,
    /// Endpoint alternativo de AWS (solo LocalStack). `None` usa el endpoint
    /// real de AWS.
    pub aws_endpoint_url: Option<url::Url>,
    /// ARN del topic SNS en el que se publican las solicitudes de escaneo.
    pub scan_requests_topic_arn: String,
    /// ARN del topic SNS en el que se publican las cancelaciones de escaneo.
    pub scan_cancellations_topic_arn: String,
    /// URL de la cola SQS de la que este Gateway consume los resultados de
    /// escaneo.
    pub scan_outcomes_queue_url: url::Url,
    /// URL de la dead-letter queue de [`Config::scan_outcomes_queue_url`].
    pub scan_outcomes_dlq_url: url::Url,
}

/// Errores posibles al cargar la configuración del servicio desde variables
/// de entorno.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Falta una variable de entorno requerida.
    #[error("falta la variable de entorno requerida: {name}")]
    Missing {
        /// Nombre de la variable de entorno ausente.
        name: &'static str,
    },
    /// Una variable de entorno numérica no se pudo parsear.
    #[error("la variable de entorno {name} no es un número válido")]
    InvalidNumber {
        /// Nombre de la variable de entorno inválida.
        name: &'static str,
        /// Error original de parseo.
        #[source]
        source: ParseIntError,
    },
    /// Una variable de entorno que debe ser una URL absoluta no se pudo
    /// parsear como tal (p. ej. `FRONT_BASE_URL` para derivar
    /// [`Config::front_origin`]).
    #[error("la variable de entorno {name} no es una URL absoluta válida")]
    InvalidUrl {
        /// Nombre de la variable de entorno inválida.
        name: &'static str,
        /// Error original de parseo.
        #[source]
        source: url::ParseError,
    },
    /// Una variable de entorno que debe ser el ARN de un topic SNS
    /// (`arn:<partición>:sns:<región>:<cuenta de 12 dígitos>:<nombre>`) no
    /// tiene esa forma. El valor no se incluye en el error.
    #[error("la variable de entorno {name} no es un ARN de topic SNS válido")]
    InvalidArn {
        /// Nombre de la variable de entorno inválida.
        name: &'static str,
    },
}

/// Lee una variable de entorno requerida como `String`.
///
/// Devuelve [`ConfigError::Missing`] si la variable no está definida o no es
/// UTF-8 válido.
fn required_string(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::Missing { name })
}

/// Lee una variable de entorno requerida que no puede estar vacía.
///
/// Devuelve [`ConfigError::Missing`] si la variable no está definida, no es
/// UTF-8 válido o está vacía.
fn required_non_empty_string(name: &'static str) -> Result<String, ConfigError> {
    required_string(name).and_then(|value| {
        if value.trim().is_empty() {
            Err(ConfigError::Missing { name })
        } else {
            Ok(value)
        }
    })
}

/// Lee una variable de entorno requerida y la parsea como URL absoluta.
fn required_url(name: &'static str) -> Result<url::Url, ConfigError> {
    let value = required_string(name)?;
    url::Url::parse(&value).map_err(|source| ConfigError::InvalidUrl { name, source })
}

/// Lee una variable de entorno opcional y, si está definida, la parsea como
/// URL absoluta. Devuelve `None` si no está definida.
fn optional_url(name: &'static str) -> Result<Option<url::Url>, ConfigError> {
    match env::var(name) {
        Ok(value) => url::Url::parse(&value)
            .map(Some)
            .map_err(|source| ConfigError::InvalidUrl { name, source }),
        Err(_) => Ok(None),
    }
}

/// Lee una variable de entorno requerida que debe ser el ARN de un topic SNS.
fn required_sns_topic_arn(name: &'static str) -> Result<String, ConfigError> {
    let value = required_string(name)?;
    if is_sns_topic_arn(&value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidArn { name })
    }
}

/// `true` si `value` tiene la forma
/// `arn:<partición>:sns:<región>:<cuenta de 12 dígitos>:<nombre>`.
fn is_sns_topic_arn(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    let [arn, partition, service, region, account, name] = parts.as_slice() else {
        return false;
    };
    *arn == "arn"
        && !partition.is_empty()
        && *service == "sns"
        && !region.is_empty()
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !name.is_empty()
}

/// Lee una variable de entorno requerida y la envuelve en [`SecretString`].
///
/// Devuelve [`ConfigError::Missing`] si la variable no está definida o no es
/// UTF-8 válido.
fn required_secret(name: &'static str) -> Result<SecretString, ConfigError> {
    required_string(name).map(SecretString::from)
}

/// Lee una variable de entorno opcional como `String`, devolviendo
/// `default` si no está definida o no es UTF-8 válido.
fn optional_string_with_default(name: &'static str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Deriva el origen (`scheme://host[:puerto]`, sin `path`) de `value`,
/// interpretado como una URL absoluta — usado para validar `FRONT_BASE_URL`
/// como [`Config::front_origin`] (feature `cors_for_front`). Devuelve
/// [`ConfigError::InvalidUrl`] si `value` no es una URL absoluta válida.
fn front_origin_from_base_url(name: &'static str, value: &str) -> Result<String, ConfigError> {
    let parsed =
        url::Url::parse(value).map_err(|source| ConfigError::InvalidUrl { name, source })?;
    Ok(parsed.origin().ascii_serialization())
}

impl Config {
    /// Carga la configuración completa del servicio desde variables de
    /// entorno.
    ///
    /// Puede fallar con [`ConfigError::Missing`] si falta alguna variable
    /// requerida, o con [`ConfigError::InvalidNumber`] si `HTTP_PORT` o
    /// `SESSION_TTL_SECS` no son numéricos. Nunca entra en pánico.
    pub fn from_env() -> Result<Self, ConfigError> {
        let http_host = required_string(ENV_HTTP_HOST)?;
        let http_port = required_string(ENV_HTTP_PORT)?
            .parse::<u16>()
            .map_err(|source| ConfigError::InvalidNumber {
                name: ENV_HTTP_PORT,
                source,
            })?;
        let google_client_id = required_string(ENV_GOOGLE_CLIENT_ID)?;
        let google_client_secret = required_secret(ENV_GOOGLE_CLIENT_SECRET)?;
        let google_redirect_uri = required_string(ENV_GOOGLE_REDIRECT_URI)?;
        let google_oidc_issuer_url = optional_string_with_default(
            ENV_GOOGLE_OIDC_ISSUER_URL,
            DEFAULT_GOOGLE_OIDC_ISSUER_URL,
        );
        let session_signing_key = required_secret(ENV_SESSION_SIGNING_KEY)?;
        let session_ttl_secs = required_string(ENV_SESSION_TTL_SECS)?
            .parse::<u64>()
            .map_err(|source| ConfigError::InvalidNumber {
                name: ENV_SESSION_TTL_SECS,
                source,
            })?;
        let front_base_url = required_string(ENV_FRONT_BASE_URL)?;
        let front_origin = front_origin_from_base_url(ENV_FRONT_BASE_URL, &front_base_url)?;
        let ms_usuarios_base_url = required_string(ENV_MS_USUARIOS_BASE_URL)?;
        let ms_usuarios_shared_secret = required_secret(ENV_MS_USUARIOS_SHARED_SECRET)?;
        let scan_submission_rate_limit_max_requests =
            required_string(ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS)?
                .parse::<u32>()
                .map_err(|source| ConfigError::InvalidNumber {
                    name: ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS,
                    source,
                })?;
        let scan_submission_rate_limit_window_secs =
            required_string(ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS)?
                .parse::<u64>()
                .map_err(|source| ConfigError::InvalidNumber {
                    name: ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS,
                    source,
                })?;
        let aws_region = required_non_empty_string(ENV_AWS_REGION)?;
        let aws_endpoint_url = optional_url(ENV_AWS_ENDPOINT_URL)?;
        let scan_requests_topic_arn = required_sns_topic_arn(ENV_SCAN_REQUESTS_TOPIC_ARN)?;
        let scan_cancellations_topic_arn =
            required_sns_topic_arn(ENV_SCAN_CANCELLATIONS_TOPIC_ARN)?;
        let scan_outcomes_queue_url = required_url(ENV_SCAN_OUTCOMES_QUEUE_URL)?;
        let scan_outcomes_dlq_url = required_url(ENV_SCAN_OUTCOMES_DLQ_URL)?;

        Ok(Self {
            http_host,
            http_port,
            google_client_id,
            google_client_secret,
            google_redirect_uri,
            google_oidc_issuer_url,
            session_signing_key,
            session_ttl_secs,
            front_base_url,
            front_origin,
            ms_usuarios_base_url,
            ms_usuarios_shared_secret,
            scan_submission_rate_limit_max_requests,
            scan_submission_rate_limit_window_secs,
            aws_region,
            aws_endpoint_url,
            scan_requests_topic_arn,
            scan_cancellations_topic_arn,
            scan_outcomes_queue_url,
            scan_outcomes_dlq_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use secrecy::ExposeSecret;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const ALL_REQUIRED_VARS: &[&str] = &[
        ENV_HTTP_HOST,
        ENV_HTTP_PORT,
        ENV_GOOGLE_CLIENT_ID,
        ENV_GOOGLE_CLIENT_SECRET,
        ENV_GOOGLE_REDIRECT_URI,
        ENV_SESSION_SIGNING_KEY,
        ENV_SESSION_TTL_SECS,
        ENV_FRONT_BASE_URL,
        ENV_MS_USUARIOS_BASE_URL,
        ENV_MS_USUARIOS_SHARED_SECRET,
        ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS,
        ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS,
        ENV_AWS_REGION,
        ENV_SCAN_REQUESTS_TOPIC_ARN,
        ENV_SCAN_CANCELLATIONS_TOPIC_ARN,
        ENV_SCAN_OUTCOMES_QUEUE_URL,
        ENV_SCAN_OUTCOMES_DLQ_URL,
    ];

    const VALID_REQUESTS_TOPIC_ARN: &str = "arn:aws:sns:us-east-1:123456789012:scan-requests";
    const VALID_CANCELLATIONS_TOPIC_ARN: &str =
        "arn:aws:sns:us-east-1:123456789012:scan-cancellations";
    const VALID_OUTCOMES_QUEUE_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes";
    const VALID_OUTCOMES_DLQ_URL: &str =
        "https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes-dlq";

    fn clear_all_vars() {
        for name in ALL_REQUIRED_VARS {
            env::remove_var(name);
        }
        env::remove_var(ENV_GOOGLE_OIDC_ISSUER_URL);
        env::remove_var(ENV_AWS_ENDPOINT_URL);
    }

    fn set_all_valid_vars() {
        env::set_var(ENV_HTTP_HOST, "0.0.0.0");
        env::set_var(ENV_HTTP_PORT, "8080");
        env::set_var(ENV_GOOGLE_CLIENT_ID, "lab-client-id");
        env::set_var(ENV_GOOGLE_CLIENT_SECRET, "lab-only-not-a-real-secret");
        env::set_var(ENV_GOOGLE_REDIRECT_URI, "https://gateway.lab/auth/callback");
        env::set_var(ENV_SESSION_SIGNING_KEY, "lab-only-not-a-real-secret");
        env::set_var(ENV_SESSION_TTL_SECS, "3600");
        env::set_var(ENV_FRONT_BASE_URL, "https://front.lab/post-login");
        env::set_var(ENV_MS_USUARIOS_BASE_URL, "http://ms-usuarios.internal");
        env::set_var(ENV_MS_USUARIOS_SHARED_SECRET, "lab-only-not-a-real-secret");
        env::set_var(ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS, "5");
        env::set_var(ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS, "60");
        env::set_var(ENV_AWS_REGION, "us-east-1");
        env::set_var(ENV_SCAN_REQUESTS_TOPIC_ARN, VALID_REQUESTS_TOPIC_ARN);
        env::set_var(
            ENV_SCAN_CANCELLATIONS_TOPIC_ARN,
            VALID_CANCELLATIONS_TOPIC_ARN,
        );
        env::set_var(ENV_SCAN_OUTCOMES_QUEUE_URL, VALID_OUTCOMES_QUEUE_URL);
        env::set_var(ENV_SCAN_OUTCOMES_DLQ_URL, VALID_OUTCOMES_DLQ_URL);
    }

    #[test]
    fn loads_valid_config_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();

        let config = Config::from_env().expect("config válida debe cargar");

        assert_eq!(config.http_host, "0.0.0.0");
        assert_eq!(config.http_port, 8080);
        assert_eq!(config.google_client_id, "lab-client-id");
        assert_eq!(
            config.google_client_secret.expose_secret(),
            "lab-only-not-a-real-secret"
        );
        assert_eq!(config.session_ttl_secs, 3600);
        assert_eq!(config.front_base_url, "https://front.lab/post-login");
        assert_eq!(
            config.front_origin, "https://front.lab",
            "front_origin debe ser el origen (sin path) de FRONT_BASE_URL"
        );
        assert_eq!(config.ms_usuarios_base_url, "http://ms-usuarios.internal");
        assert_eq!(
            config.google_oidc_issuer_url, DEFAULT_GOOGLE_OIDC_ISSUER_URL,
            "sin GOOGLE_OIDC_ISSUER_URL debe usarse el issuer real de Google por defecto"
        );
        assert_eq!(config.scan_submission_rate_limit_max_requests, 5);
        assert_eq!(config.scan_submission_rate_limit_window_secs, 60);
        assert_eq!(config.aws_region, "us-east-1");
        assert_eq!(config.aws_endpoint_url, None);
        assert_eq!(config.scan_requests_topic_arn, VALID_REQUESTS_TOPIC_ARN);
        assert_eq!(
            config.scan_cancellations_topic_arn,
            VALID_CANCELLATIONS_TOPIC_ARN
        );
        assert_eq!(
            config.scan_outcomes_queue_url.as_str(),
            VALID_OUTCOMES_QUEUE_URL
        );
        assert_eq!(
            config.scan_outcomes_dlq_url.as_str(),
            VALID_OUTCOMES_DLQ_URL
        );

        clear_all_vars();
    }

    #[test]
    fn aws_endpoint_url_present_and_valid_is_some() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_AWS_ENDPOINT_URL, "http://localstack:4566");

        let config = Config::from_env().expect("config válida debe cargar");

        assert_eq!(
            config.aws_endpoint_url.as_ref().map(url::Url::as_str),
            Some("http://localstack:4566/")
        );

        clear_all_vars();
    }

    #[test]
    fn aws_endpoint_url_invalid_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_AWS_ENDPOINT_URL, "not-a-url");

        let result = Config::from_env();

        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidUrl {
                    name: ENV_AWS_ENDPOINT_URL,
                    ..
                })
            ),
            "esperaba ConfigError::InvalidUrl para {ENV_AWS_ENDPOINT_URL}, obtuve {result:?}"
        );

        clear_all_vars();
    }

    #[test]
    fn empty_aws_region_is_treated_as_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_AWS_REGION, "");

        let result = Config::from_env();

        assert!(
            matches!(
                result,
                Err(ConfigError::Missing {
                    name: ENV_AWS_REGION
                })
            ),
            "esperaba ConfigError::Missing para {ENV_AWS_REGION}, obtuve {result:?}"
        );

        clear_all_vars();
    }

    #[test]
    fn malformed_topic_arns_produce_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        let malformed = [
            "not-an-arn",
            "arn:aws:sqs:us-east-1:123456789012:scan-requests",
            "arn:aws:sns:us-east-1:123456789012",
            "arn:aws:sns:us-east-1:12345:scan-requests",
            "arn:aws:sns:us-east-1:123456789012:",
            "arn:aws:sns::123456789012:scan-requests",
            "arn::sns:us-east-1:123456789012:scan-requests",
        ];

        for name in [
            ENV_SCAN_REQUESTS_TOPIC_ARN,
            ENV_SCAN_CANCELLATIONS_TOPIC_ARN,
        ] {
            for value in malformed {
                clear_all_vars();
                set_all_valid_vars();
                env::set_var(name, value);

                let result = Config::from_env();

                assert!(
                    matches!(result, Err(ConfigError::InvalidArn { name: n }) if n == name),
                    "esperaba ConfigError::InvalidArn para {name}={value}, obtuve {result:?}"
                );
            }
        }

        clear_all_vars();
    }

    #[test]
    fn malformed_queue_urls_produce_invalid_url_error() {
        let _guard = ENV_LOCK.lock().unwrap();

        for name in [ENV_SCAN_OUTCOMES_QUEUE_URL, ENV_SCAN_OUTCOMES_DLQ_URL] {
            clear_all_vars();
            set_all_valid_vars();
            env::set_var(name, "not-a-url");

            let result = Config::from_env();

            assert!(
                matches!(result, Err(ConfigError::InvalidUrl { name: n, .. }) if n == name),
                "esperaba ConfigError::InvalidUrl para {name}, obtuve {result:?}"
            );
        }

        clear_all_vars();
    }

    #[test]
    fn google_oidc_issuer_url_can_be_overridden_for_tests() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_GOOGLE_OIDC_ISSUER_URL, "http://127.0.0.1:12345");

        let config = Config::from_env().expect("config válida debe cargar");

        assert_eq!(config.google_oidc_issuer_url, "http://127.0.0.1:12345");

        clear_all_vars();
    }

    #[test]
    fn missing_each_required_var_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();

        for name in ALL_REQUIRED_VARS {
            clear_all_vars();
            set_all_valid_vars();
            env::remove_var(name);

            let result = Config::from_env();

            assert!(
                matches!(result, Err(ConfigError::Missing { name: missing }) if missing == *name),
                "esperaba ConfigError::Missing para {name}, obtuve {result:?}"
            );
        }

        clear_all_vars();
    }

    #[test]
    fn non_numeric_http_port_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_HTTP_PORT, "not-a-number");

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidNumber {
                name: ENV_HTTP_PORT,
                ..
            })
        ));

        clear_all_vars();
    }

    #[test]
    fn non_numeric_session_ttl_secs_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_SESSION_TTL_SECS, "not-a-number");

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidNumber {
                name: ENV_SESSION_TTL_SECS,
                ..
            })
        ));

        clear_all_vars();
    }

    #[test]
    fn non_numeric_scan_submission_rate_limit_max_requests_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS, "not-a-number");

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidNumber {
                name: ENV_SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS,
                ..
            })
        ));

        clear_all_vars();
    }

    #[test]
    fn non_numeric_scan_submission_rate_limit_window_secs_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS, "not-a-number");

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidNumber {
                name: ENV_SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS,
                ..
            })
        ));

        clear_all_vars();
    }

    #[test]
    fn front_base_url_that_is_not_an_absolute_url_produces_typed_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();
        env::set_var(ENV_FRONT_BASE_URL, "not-an-absolute-url");

        let result = Config::from_env();

        assert!(
            matches!(
                result,
                Err(ConfigError::InvalidUrl {
                    name: ENV_FRONT_BASE_URL,
                    ..
                })
            ),
            "esperaba ConfigError::InvalidUrl para {ENV_FRONT_BASE_URL}, obtuve {result:?}"
        );

        clear_all_vars();
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();

        let config = Config::from_env().expect("config válida debe cargar");
        let debug_output = format!("{config:?}");

        clear_all_vars();

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(debug_output.contains("REDACTED"));
    }
}
