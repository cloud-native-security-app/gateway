# Review — feature 2 (config)

**Veredicto:** APPROVED

## Verificación de comandos (ejecutados por el reviewer, no solo confiando en el reporte del implementer)

- `cargo build 2>&1` → `Finished` sin warnings.
- `cargo clippy --all-targets -- -D warnings 2>&1` → `Finished`, sin advertencias.
- `cargo fmt --check` → exit 0, sin diferencias.
- `cargo test 2>&1` → `5 passed; 0 failed` en `config::tests` (resto del crate: 0 tests, esperado para esta feature).
- `./init.sh` → las 5 secciones en `[OK]`, exit code 0 (incluye `cargo test -- --ignored` sin tests de integración pendientes, correcto: esta feature no cruza IO real).

## Criterios de aceptación (feature id=2, `feature_list.json`)

1. **Carga desde las 11 vars de entorno con error tipado si falta una, sin panics** — PASA.
   Evidencia: `src/config.rs:121-141` lee `HTTP_HOST`, `HTTP_PORT`, `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `SESSION_SIGNING_KEY`, `SESSION_TTL_SECS`,
   `BROKER_AMQPS_URL`, `BROKER_VHOST`, `MS_USUARIOS_BASE_URL`, `MS_USUARIOS_SHARED_SECRET`
   (10 nombres del criterio + `SESSION_TTL_SECS` ya contado; son 11 en total incluyendo
   `HTTP_HOST`/`HTTP_PORT` por separado). `required_string`/`required_secret`
   (`src/config.rs:101-111`) usan `env::var(...).map_err(|_| ConfigError::Missing { name })`,
   ningún `.unwrap()`/`.expect()`/`panic!` fuera de `#[cfg(test)]` (confirmado leyendo el
   archivo completo línea por línea; el único `.unwrap()` está en
   `ENV_LOCK.lock().unwrap()` dentro de `mod tests`, permitido por
   `docs/conventions.md`). `HTTP_PORT`/`SESSION_TTL_SECS` usan `.parse()` con
   `ConfigError::InvalidNumber` (`src/config.rs:122-137`), nunca `.unwrap()`.
   Test `missing_each_required_var_produces_typed_error` (`src/config.rs:233-251`)
   itera las 11 variables una por una y verifica `ConfigError::Missing{name}` con el
   nombre exacto — verde.

2. **`SecretString` en los 4 secretos, redacción en Debug/Display** — PASA.
   Evidencia: `google_client_secret`, `session_signing_key`, `broker_amqps_url`,
   `ms_usuarios_shared_secret` son `secrecy::SecretString` (`src/config.rs:56,61,66,73`).
   `secrecy::SecretString` no implementa `Display` (falla de compilar si se intentara
   `{}` sobre un secreto) y su `Debug` imprime `REDACTED`. Verificado no solo por el
   reporte del implementer sino por el test `debug_does_not_leak_secrets`
   (`src/config.rs:293-307`), que formatea el `Config` completo con `{config:?}` y
   confirma que ni `"lab-only-not-a-real-secret"` ni la URL AMQPS completa de laboratorio
   aparecen en el output, y que sí contiene `"REDACTED"` — verde en `cargo test`.

3. **Nada hardcodeado** — PASA.
   Revisión línea por línea de `src/config.rs`: los únicos literales string fuera de
   `#[cfg(test)]` son los 11 *nombres* de variables de entorno (`ENV_HTTP_HOST = "HTTP_HOST"`,
   etc., líneas 11-38) — ningún valor (URL, client id, puerto, secreto) está hardcodeado;
   todos los valores vienen de `env::var`. Los literales de tipo `"lab-only-not-a-real-secret"`,
   `"0.0.0.0"`, etc. solo existen dentro de `mod tests` como fixtures de laboratorio, que
   `docs/security-scope.md` permite explícitamente para datos de prueba.

4. **Cobertura de tests: config válida carga, cada var faltante produce error tipado,
   Debug no filtra secretos** — PASA. Los 5 tests en `#[cfg(test)] mod tests`
   (`src/config.rs:159-308`) cubren exactamente eso más los dos casos de número inválido
   (`HTTP_PORT`, `SESSION_TTL_SECS`), superando el mínimo pedido. Los tests comparten
   variables de entorno de proceso y usan `static ENV_LOCK: Mutex<()>` para serializarse
   correctamente entre sí (evita carreras si `cargo test` los ejecuta en threads paralelos).

## Conformidad con `docs/conventions.md`

- Doc-comment de módulo `//!` al inicio (`src/config.rs:1-2`) — cumple.
- Imports ordenados std → crates externos (`src/config.rs:4-7`) — cumple.
- `thiserror::Error` con variantes específicas (`Missing`, `InvalidNumber`), no `String`
  genérico (`src/config.rs:78-95`) — cumple.
- Rustdoc `///` en todo ítem público: `Config`, cada campo, `ConfigError` y sus variantes,
  `Config::from_env` — cumple; confirmado además por `cargo doc --no-deps` (parte de
  `./init.sh`) sin errores bajo `#![deny(missing_docs)]` de `src/lib.rs:8`.
- Tests unitarios en `#[cfg(test)] mod tests` al final del archivo, para lógica pura sin
  IO real más allá de `std::env` — cumple con el patrón documentado.
- Nombres: `snake_case` en funciones/campos, `PascalCase` en tipos, `UPPER_SNAKE` en
  constantes `ENV_*` — cumple.
- `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` verdes — cumple.

## Conformidad con `docs/security-scope.md`

- Los 4 secretos (`GOOGLE_CLIENT_SECRET`, `SESSION_SIGNING_KEY`, `BROKER_AMQPS_URL`,
  `MS_USUARIOS_SHARED_SECRET` vía `ms_usuarios_shared_secret`) usan `SecretString` y jamás
  se exponen vía `Debug`/`Display` de la struct completa — verificado con test, no solo
  inspección.
- No hay ninguna credencial real en el repo; los fixtures de test usan el patrón
  `"lab-only-not-a-real-secret"` que exige el doc para datos sintéticos de laboratorio.
- Nota de nomenclatura (documentada, no un fallo): `docs/security-scope.md` nombra la
  credencial de `ms-usuarios` como `GATEWAY_SHARED_SECRET`, pero el criterio de aceptación
  explícito de `feature_list.json` id=2 usa `MS_USUARIOS_SHARED_SECRET`. El implementer
  siguió el criterio de aceptación (fuente de verdad de la feature) y dejó la discrepancia
  documentada en `progress/current.md` y `progress/impl_config.md`. No es una violación de
  seguridad (ambos nombres describen la misma credencial de servicio hacia `ms-usuarios`,
  nunca hardcodeada ni logueada) — queda como nota para que el `leader` decida si
  actualiza `docs/security-scope.md` para converger el nombre en una sesión futura.
- Esta feature no introduce ninguna ruta HTTP; no aplica el punto de RF-10 (middleware de
  sesión) todavía.

## Checkpoints (`CHECKPOINTS.md`), solo los verificables en el alcance de esta feature

- C1 (arnés completo, `./init.sh` exit 0): [x]
- C2 (a lo más 1 feature `in_progress`, feature `done` con tests, `progress/current.md`
  coherente): [x] — solo la feature 2 está `in_progress` en `feature_list.json`;
  `progress/current.md` refleja la sesión activa sin basura de sesiones anteriores.
  (Feature 2 sigue en `in_progress`, no `done`, hasta que el leader cierre el ciclo —
  correcto, no corresponde a este reviewer cambiar el estado.)
- C3 (arquitectura): [x] — `src/config.rs` es el único archivo tocado en `src/`, coherente
  con la capa `config` de `docs/architecture.md` §Capas; las dos dependencias nuevas
  (`secrecy`, `thiserror`) están justificadas por el criterio de aceptación de esta
  feature y por `docs/conventions.md` (errores con `thiserror`); sin `println!`/`dbg!`/
  `unwrap`/`panic!` fuera de tests; `cargo doc --no-deps` sin warnings; no se inventó
  shape de ninguna API pendiente (no aplica a esta feature).
- C4 (verificación real): [ ] — no aplica completo todavía: esta feature no tiene tests
  de integración cruzando IO real (no le corresponde; `config` es lógica pura sobre
  `std::env`, cubierta por tests unitarios). `cargo test` > 0 tests y todos verdes, y
  `cargo clippy` sin warnings sí se cumplen para el alcance actual del repo. Se marca
  parcial porque el checkpoint pide "al menos un test de integración por módulo que
  cruza IO" a nivel de repo completo, y todavía no existen los módulos `auth`,
  `usuarios_client`, `broker`, `api` (features 3+, `pending`) — no es un fallo de esta
  feature, es un estado esperado en este punto del proyecto.
- C5 (cierre de sesión): [ ] — pendiente de que el `leader` cierre la sesión (mover
  entrada a `progress/history.md`, actualizar `status` de la feature). No corresponde a
  este reviewer.

## Cambios requeridos

Ninguno. Sugerencia no bloqueante para una sesión futura: alinear el nombre de la
credencial de `ms-usuarios` entre `docs/security-scope.md` (`GATEWAY_SHARED_SECRET`) y
`feature_list.json`/`src/config.rs` (`MS_USUARIOS_SHARED_SECRET`) para evitar confusión
en la feature `usuarios_profile_proxy` (id=5).
