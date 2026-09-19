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
/// Nombre de la variable de entorno con la URL AMQPS del Broker (incluye la
/// credencial del usuario RabbitMQ `gateway`).
const ENV_BROKER_AMQPS_URL: &str = "BROKER_AMQPS_URL";
/// Nombre de la variable de entorno con el vhost de RabbitMQ a usar en el
/// Broker.
const ENV_BROKER_VHOST: &str = "BROKER_VHOST";
/// Nombre de la variable de entorno con la URL base de `ms-usuarios`.
const ENV_MS_USUARIOS_BASE_URL: &str = "MS_USUARIOS_BASE_URL";
/// Nombre de la variable de entorno con la credencial de servicio
/// compartida con `ms-usuarios`.
const ENV_MS_USUARIOS_SHARED_SECRET: &str = "MS_USUARIOS_SHARED_SECRET";

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
    /// URL AMQPS del Broker, incluida la credencial del usuario RabbitMQ
    /// `gateway`. Nunca se loggea.
    pub broker_amqps_url: SecretString,
    /// Vhost de RabbitMQ a usar en el Broker.
    pub broker_vhost: String,
    /// URL base de `ms-usuarios`, nunca expuesta a `front`.
    pub ms_usuarios_base_url: String,
    /// Credencial de servicio compartida con `ms-usuarios`. Nunca se
    /// loggea.
    pub ms_usuarios_shared_secret: SecretString,
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
}

/// Lee una variable de entorno requerida como `String`.
///
/// Devuelve [`ConfigError::Missing`] si la variable no está definida o no es
/// UTF-8 válido.
fn required_string(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::Missing { name })
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
        let broker_amqps_url = required_secret(ENV_BROKER_AMQPS_URL)?;
        let broker_vhost = required_string(ENV_BROKER_VHOST)?;
        let ms_usuarios_base_url = required_string(ENV_MS_USUARIOS_BASE_URL)?;
        let ms_usuarios_shared_secret = required_secret(ENV_MS_USUARIOS_SHARED_SECRET)?;

        Ok(Self {
            http_host,
            http_port,
            google_client_id,
            google_client_secret,
            google_redirect_uri,
            google_oidc_issuer_url,
            session_signing_key,
            session_ttl_secs,
            broker_amqps_url,
            broker_vhost,
            ms_usuarios_base_url,
            ms_usuarios_shared_secret,
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
        ENV_BROKER_AMQPS_URL,
        ENV_BROKER_VHOST,
        ENV_MS_USUARIOS_BASE_URL,
        ENV_MS_USUARIOS_SHARED_SECRET,
    ];

    /// Valor de laboratorio para `BROKER_AMQPS_URL`, no una credencial real
    /// (ver `docs/security-scope.md`).
    const LAB_BROKER_AMQPS_URL: &str = "amqps://gateway:lab-only-not-a-real-secret@broker.lab:5671";

    fn clear_all_vars() {
        for name in ALL_REQUIRED_VARS {
            env::remove_var(name);
        }
        env::remove_var(ENV_GOOGLE_OIDC_ISSUER_URL);
    }

    fn set_all_valid_vars() {
        env::set_var(ENV_HTTP_HOST, "0.0.0.0");
        env::set_var(ENV_HTTP_PORT, "8080");
        env::set_var(ENV_GOOGLE_CLIENT_ID, "lab-client-id");
        env::set_var(ENV_GOOGLE_CLIENT_SECRET, "lab-only-not-a-real-secret");
        env::set_var(ENV_GOOGLE_REDIRECT_URI, "https://gateway.lab/auth/callback");
        env::set_var(ENV_SESSION_SIGNING_KEY, "lab-only-not-a-real-secret");
        env::set_var(ENV_SESSION_TTL_SECS, "3600");
        env::set_var(ENV_BROKER_AMQPS_URL, LAB_BROKER_AMQPS_URL);
        env::set_var(ENV_BROKER_VHOST, "security-app");
        env::set_var(ENV_MS_USUARIOS_BASE_URL, "http://ms-usuarios.internal");
        env::set_var(ENV_MS_USUARIOS_SHARED_SECRET, "lab-only-not-a-real-secret");
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
        assert_eq!(
            config.broker_amqps_url.expose_secret(),
            LAB_BROKER_AMQPS_URL
        );
        assert_eq!(config.broker_vhost, "security-app");
        assert_eq!(config.ms_usuarios_base_url, "http://ms-usuarios.internal");
        assert_eq!(
            config.google_oidc_issuer_url, DEFAULT_GOOGLE_OIDC_ISSUER_URL,
            "sin GOOGLE_OIDC_ISSUER_URL debe usarse el issuer real de Google por defecto"
        );

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
    fn debug_does_not_leak_secrets() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all_vars();
        set_all_valid_vars();

        let config = Config::from_env().expect("config válida debe cargar");
        let debug_output = format!("{config:?}");

        clear_all_vars();

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(!debug_output.contains(LAB_BROKER_AMQPS_URL));
        assert!(debug_output.contains("REDACTED"));
    }
}
