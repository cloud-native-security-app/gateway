# Review — feature 12 (post_login_redirect)

**Veredicto:** APPROVED

## Criterios de aceptación (feature_list.json, id=12)

1. **Nueva variable `FRONT_BASE_URL` en `src/config.rs`, mismo patrón que el resto — PASA.**
   `src/config.rs:46` declara `ENV_FRONT_BASE_URL = "FRONT_BASE_URL"`; `Config::from_env` (línea 189) la lee con `required_string`, igual que el resto de variables requeridas de tipo `String` (p. ej. `broker_vhost`) → `ConfigError::Missing { name }` si falta, sin `panic!`/`unwrap`. Es `String`, no `SecretString` — correcto, no es una credencial. Añadida a `ALL_REQUIRED_VARS` (línea 247) y cubierta por `loads_valid_config_from_env`, `missing_each_required_var_produces_typed_error` (recorre todas las vars incluida esta) y `debug_does_not_leak_secrets`.

2. **`GET /auth/callback` responde 302 con `Location` fijo al valor configurado, nunca derivado de la query string — PASA.**
   `src/api.rs:1148`: `Ok((jar.add(cookie), redirect_found(&state.front_base_url)))`. `redirect_found` (línea 1169) solo escribe `location.to_string()` en el header `Location` — no interpola ni lee `params`. `CallbackParams` (línea 1075) solo modela `code`/`state`; con Axum/serde, campos de query no declarados en el struct simplemente se ignoran (no hay `deny_unknown_fields`), así que un atacante añadiendo `redirect_uri`/`next` a la query no puede influir en absoluto el `Location`. Verificado también en runtime: el test `callback_success_redirect_ignores_extra_query_params` agrega `redirect_uri`/`next` maliciosos y confirma `Location == TEST_FRONT_BASE_URL` exactamente.

3. **Doc OpenAPI de `GET /auth/callback` actualizada (200 → 302 en camino feliz) — PASA.**
   `src/api.rs:1103-1114`: la respuesta `200` fue reemplazada por `302` con descripción explícita ("el header Location redirige siempre a la URL de front fijada en configuración... nunca a un valor derivado de la request"); se mantienen `400`/`401`/`500` documentados igual que antes. `tests/openapi_docs.rs` (2/2 tests) sigue en verde, validando que el spec generado es JSON válido y cubre las rutas esperadas.

4. **Los casos de error existentes (400/401) no cambian de comportamiento — PASA.**
   `src/api.rs:1186-1202` (`impl IntoResponse for AuthError`): el mapeo de variantes a status (`MissingState`/`InvalidState`/`MissingCode` → 400; `IdTokenExpired`/`IdTokenInvalidSignature`/`IdTokenInvalidAudienceOrIssuer`/`IdTokenInvalidNonce`/`IdTokenRejected`/`SessionInvalid` → 401; `Discovery`/`SessionIssue` → 500) no fue tocado por esta feature. Los tests `callback_rejects_id_token_with_wrong_audience`, `callback_rejects_expired_id_token`, `callback_rejects_id_token_with_invalid_signature`, `callback_rejects_missing_state`, `callback_rejects_state_that_does_not_match_any_pending_login` siguen verificando 400/401 sin `Set-Cookie`, sin `Location` — todos en verde.

5. **`tests/oidc_login.rs` actualizado (302 + Location en éxito, nuevo test de query maliciosa) — PASA.**
   `callback_with_valid_id_token_creates_session` (línea 381) ahora espera `StatusCode::FOUND` y `Location == TEST_FRONT_BASE_URL`, y sigue verificando `Set-Cookie` `HttpOnly`/`Secure`/`SameSite=Strict` y que el ID token crudo de Google nunca aparece en el cuerpo de la respuesta. `callback_success_redirect_ignores_extra_query_params` (línea 480) es nuevo, exactamente como pide el acceptance. 9/9 tests de `tests/oidc_login.rs` pasan.

6. **`cargo test` (incluido `--ignored`) y `./init.sh` en verde — PASA.**
   Ejecutado `./init.sh` de forma independiente en este entorno (Docker disponible): `cargo fmt --check` sin diferencias, `cargo clippy --all-targets -- -D warnings` sin advertencias, 54 tests unitarios + toda la suite de `tests/*.rs` (incluidos los 3 marcados `#[ignore = "requiere Docker"]` de `scan_history_and_cancellation`, `scan_outcome_relay`, `scan_submission`, ejecutados vía `cargo test -- --ignored` contra RabbitMQ real por `testcontainers`) en verde, `cargo doc --no-deps` sin errores. Exit code final `0`.

## Otras verificaciones (`docs/security-scope.md` / `docs/architecture.md` / `docs/conventions.md`)

- **Sin fuga de credenciales/tokens:** `redirect_found` solo escribe la URL fija de configuración en `Location`; no se toca el ID token de Google, la sesión firmada, `MS_USUARIOS_SHARED_SECRET` ni `BROKER_AMQPS_URL` en ningún punto de este cambio. `front_base_url` es un dato público (URL de `front`), correctamente modelado como `String` y no `SecretString`.
- **RF-10 (rutas protegidas):** esta feature no toca el middleware de sesión ni el router de rutas protegidas; `/auth/callback` sigue siendo pública por diseño (necesaria para completar el login), sin cambios en qué rutas llevan `require_session`.
- **Capas (`docs/architecture.md`):** el cambio respeta la capa `api` (handler + `AppState`), `config` (nueva var) y `wiring` (paso del valor al estado) sin introducir módulos nuevos ni tocar `domain`/`auth`/`usuarios_client`/`broker`/`realtime` fuera de lo necesario.
- **Convenciones:** nombres (`FRONT_BASE_URL`, `front_base_url`, `ENV_FRONT_BASE_URL`) siguen `UPPER_SNAKE`/`snake_case` como el resto de `config.rs`; rustdoc presente en el campo público `Config::front_base_url` y `AppState::front_base_url`, explicando explícitamente el motivo de seguridad (comentario "por qué", no "qué", conforme a `docs/conventions.md`).
- **Tests de `AppState` en otros archivos (`rate_limiting.rs`, `scan_submission.rs`, `scan_history_and_cancellation.rs`, `scan_outcome_relay.rs`, `session_middleware_and_me.rs`, `usuarios_profile_proxy.rs`):** revisados uno por uno — cada uno solo agrega el campo `front_base_url: "https://front.lab".to_string()` al literal de `AppState` ya existente, sin tocar ninguna aserción de esos tests. No hay cambio de comportamiento fuera del scope de esta feature.
- **README.md:** `FRONT_BASE_URL` documentada en la tabla de env vars (línea 71) y en el ejemplo de `docker run` (línea 88), con valores sintéticos.
- **No se inventó ningún shape de API pendiente** (no aplica a esta feature — no toca `ms-usuarios` ni el Broker).

## Checkpoints (`CHECKPOINTS.md`)

- **C1** — [x] Existen los 4 archivos base y los 4 docs; `./init.sh` terminó con exit code 0 (verificado en este entorno, con Docker disponible).
- **C2** — [x] Solo la feature 12 está `in_progress` en `feature_list.json` (features 1-11 en `done`); toda feature `done` tiene tests que pasan (confirmado por `./init.sh`); `progress/current.md` describe la sesión activa (feature 12) sin basura de sesiones previas.
- **C3** — [x] `src/` solo contiene los módulos previstos (`config`, `domain`, `auth`, `usuarios_client`, `broker`, `realtime`, `api`, `wiring`, más `lib`/`main`); esta feature no agrega dependencias a `Cargo.toml` (no las necesita); no hay `println!`/`dbg!` nuevos ni `unwrap()`/`panic!()` fuera de `#[cfg(test)] mod tests` (verificado con grep en todo `src/`, cada ocurrencia cae después de la línea `mod tests` de su archivo); `cargo doc --no-deps` genera sin errores; no se inventó el shape de ninguna API pendiente.
- **C4** — [x] Los tests de integración de `broker`/`usuarios_client`/`api` siguen corriendo contra RabbitMQ real vía `testcontainers` (confirmado por los tiempos ~5-6s de los 3 tests `--ignored` en la salida de `./init.sh`, consistentes con levantar un contenedor real, no un mock); `cargo test` muestra 54 + 9 + 2 + 3 + 4 + 3 + 5 + 8 + 3 = tests > 0, todos verdes (0 failed en ambas pasadas, normal y `--ignored`); `cargo clippy --all-targets -- -D warnings` sin advertencias.
- **C5** — [x] No hay archivos sin trackear sospechosos (sin `*.tmp`; `target/` cubierto por `.gitignore`); `progress/history.md` aún no tiene entrada de la feature 12 — correcto, esa entrada se añade al cerrar la sesión tras este veredicto, no antes (mismo patrón que el review previo de la feature 11); el estado de la feature 12 en `feature_list.json` sigue correctamente en `in_progress` (el `reviewer` no marca `done`, eso ocurre después de este veredicto).

## Cambios requeridos

Ninguno.
