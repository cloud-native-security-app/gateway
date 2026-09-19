# Implementación — feature 2: config

## Archivos creados/modificados

- `src/config.rs` (reescrito por completo, antes solo tenía el doc-comment
  de módulo del scaffolding): carga de `Config` desde variables de entorno,
  `ConfigError` (`thiserror`), tests unitarios.
- `Cargo.toml`: se añadieron `secrecy = "0.10.3"` (dependencia normal, sin
  features extra) y `thiserror = "2.0.20"` (dependencia normal), ambas vía
  `cargo add` para fijar versiones resueltas por cargo, no inventadas a
  mano.
- `Cargo.lock`: actualizado por `cargo add`/`cargo build`.

No se tocó ningún otro archivo de `src/`, `tests/`, ni `feature_list.json`.

## Diseño

- `Config` es un struct público con un campo por variable de entorno
  requerida. Los 4 campos que transportan una credencial
  (`google_client_secret`, `session_signing_key`, `broker_amqps_url`,
  `ms_usuarios_shared_secret`) son `secrecy::SecretString`. Verifiqué la API
  exacta del crate (extraje el `.crate` 0.10.3 y leí `src/lib.rs`): `Debug`
  está implementado y siempre imprime `SecretBox<str>([REDACTED])`, y **no
  existe** impl de `Display` — así que un intento accidental de usar
  `{}` sobre un secreto es un error de compilación, no solo un
  riesgo de runtime.
- `Config::from_env()` devuelve `Result<Config, ConfigError>`. `ConfigError`
  tiene dos variantes: `Missing { name }` (variable ausente o no UTF-8) e
  `InvalidNumber { name, source }` (para `HTTP_PORT`/`SESSION_TTL_SECS` no
  parseables), siguiendo el patrón de `docs/conventions.md` (variantes
  específicas, no `String`). Ningún `unwrap`/`expect`/`panic!` en el código
  de `src/` (fuera de `#[cfg(test)]`).
- Nombres de variables de entorno como constantes privadas
  (`ENV_HTTP_HOST`, etc.) para no hardcodear literales repetidos y para que
  los tests puedan iterar sobre `ALL_REQUIRED_VARS`.
- Sin lógica de negocio de otras features: no se toca OIDC, Broker AMQP, ni
  HTTP client de `ms-usuarios` — solo carga y tipado de configuración.

## Verificación de cada criterio de aceptación

1. **Carga desde env vars, error explícito si falta una requerida, sin
   panics** — cubierto por `required_string`/`required_secret` (usan
   `env::var(...).map_err(...)`, nunca `.unwrap()`) y el test
   `missing_each_required_var_produces_typed_error`, que quita una por una
   las 11 variables (incluyendo `HTTP_PORT` y `SESSION_TTL_SECS`) sobre una
   config por lo demás válida y verifica `ConfigError::Missing { name }`
   con el nombre correcto. Verificado en verde (`cargo test`).
2. **`SecretString` en los 4 secretos** — `google_client_secret`,
   `session_signing_key`, `broker_amqps_url`, `ms_usuarios_shared_secret`
   son `secrecy::SecretString`. Test `debug_does_not_leak_secrets` formatea
   el `Config` completo con `{:?}` y afirma que ni el secreto compartido de
   laboratorio (`"lab-only-not-a-real-secret"`) ni la URL AMQPS completa de
   laboratorio aparecen en la salida, y que sí aparece `REDACTED`. Verde.
3. **Nada hardcodeado** — revisión manual: todo valor de `Config` proviene
   de `env::var`; los únicos literales de `src/config.rs` son los *nombres*
   de las variables de entorno (constantes `ENV_*`), no sus valores.
4. **Cobertura de test** — 5 tests en `#[cfg(test)] mod tests` al final del
   archivo (lógica pura, sin I/O real más allá de `std::env`, coherente con
   `docs/conventions.md`):
   - `loads_valid_config_from_env`
   - `missing_each_required_var_produces_typed_error`
   - `non_numeric_http_port_produces_typed_error`
   - `non_numeric_session_ttl_secs_produces_typed_error`
   - `debug_does_not_leak_secrets`
   Los tests comparten variables de entorno de proceso, así que usan un
   `static ENV_LOCK: Mutex<()>` para serializarse entre sí y evitar carreras
   si `cargo test` los corre en threads distintos.
   El valor de laboratorio usado para `BROKER_AMQPS_URL` sigue el patrón
   `"lab-only-not-a-real-secret"` que exige `docs/security-scope.md` para
   credenciales de prueba.

## Resultado de comandos de verificación

- `cargo build 2>&1` → compila sin warnings.
- `cargo clippy --all-targets -- -D warnings 2>&1` → sin advertencias.
- `cargo fmt --check` → sin diferencias (tras `cargo fmt`, que reformateó
  dos líneas largas en los tests).
- `cargo test 2>&1` → `5 passed; 0 failed` en `config::tests`, resto del
  crate sin tests todavía (`src/main.rs`, doctests) en verde.
- `./init.sh` → todas las secciones `[OK]`, exit code 0 (incluye
  `cargo test -- --ignored`, que no encuentra tests de integración
  ignorados todavía — correcto para esta feature, que no tiene I/O real).

## Dudas / bloqueos

Ninguno. Nota ya dejada en `progress/current.md` por el leader antes de
despachar esta tarea: `docs/security-scope.md` nombra la credencial de
`ms-usuarios` como `GATEWAY_SHARED_SECRET`, pero el criterio de aceptación
explícito de `feature_list.json` (id=2) usa `MS_USUARIOS_SHARED_SECRET` —
se siguió el nombre de `feature_list.json` por ser el criterio de
aceptación exacto de esta feature.

No se cambió `status` en `feature_list.json` ni se movió nada a
`progress/history.md` — corresponde al `leader` tras el veredicto del
`reviewer`.
