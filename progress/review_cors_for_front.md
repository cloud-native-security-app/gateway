# Review — feature 13 (cors_for_front)

**Veredicto:** APPROVED

## Verificación realizada

- `./init.sh` ejecutado de forma independiente (no solo lo reportado por el
  implementer): termina con exit code `0`. `cargo fmt --check` sin
  diferencias, `cargo clippy --all-targets -- -D warnings` sin advertencias,
  `cargo test` → 55/55 en verde (incluye los 4 nuevos de `tests/cors.rs` y
  el nuevo `front_base_url_that_is_not_an_absolute_url_produces_typed_error`
  + assert de `front_origin` en `config.rs`), `cargo test -- --ignored` → 3
  tests de integración contra RabbitMQ real vía `testcontainers` (Docker
  disponible en este entorno) en verde, `cargo doc --no-deps` sin errores ni
  warnings.
- Archivos revisados línea por línea: `Cargo.toml`, `src/config.rs`,
  `src/wiring.rs`, `src/api.rs` (secciones `AppState`, `app_router`,
  `cors_layer`, `ROUTES`), `tests/cors.rs`, y los 7 archivos de test que
  solo agregaron el campo `front_origin`.

## Puntos técnicos evaluados

1. **`FRONT_BASE_URL` reutilizada, no inventada.** `src/config.rs:99-109`
   (`Config::front_origin`) y `src/config.rs:183-187`
   (`front_origin_from_base_url`, usa `url::Url::parse(...).origin()
   .ascii_serialization()`) derivan el origen de la misma variable de la
   feature 12, sin introducir una env var nueva. `README.md:71,88` confirma
   que `FRONT_BASE_URL` lleva `path` en ejemplos reales
   (`https://front.example/post-login`), y el test
   `loads_valid_config_from_env` (`src/config.rs:336-340`) verifica que
   `front_origin == "https://front.lab"` a partir de
   `"https://front.lab/post-login"`. Es una normalización correcta del
   mismo valor de configuración (RFC 6454, el header `Origin` nunca lleva
   `path`), no una desviación del acceptance — al contrario, usar el string
   crudo hubiera sido el bug (el predicate nunca habría igualado un
   `Origin` real de navegador).
2. **`allow_credentials(true)` + origen exacto, nunca wildcard**:
   `src/api.rs:1014-1021` (`cors_layer`). Confirmado por
   `get_me_with_allowed_origin_receives_correct_cors_headers`
   (`tests/cors.rs:222-258`): `Access-Control-Allow-Origin` refleja
   exactamente `TEST_FRONT_ORIGIN` y `Access-Control-Allow-Credentials:
   true`.
3. **`AllowOrigin::predicate` en vez de `AllowOrigin::exact`**: el
   comentario en `src/api.rs:1001-1010` documenta correctamente el motivo
   (con `exact`/`allow_origin(HeaderValue)`, tower-http fija un único valor
   de `Access-Control-Allow-Origin` en toda respuesta sin comparar contra
   el `Origin` real de la request). El test
   `get_me_with_disallowed_origin_does_not_receive_allow_origin_header`
   (`tests/cors.rs:309-337`) lo cubre exactamente y pasa: `Origin:
   https://evil.example` no recibe la cabecera, mientras la request se
   sigue procesando normalmente (`200 OK`, la sesión sigue siendo válida).
4. **`CorsLayer` como capa externa, tras fusionar `protected_router`**:
   `src/api.rs:981-989` (`app_router`) aplica `.layer(cors)` después de
   `.merge(protected_router(state))`, que a su vez lleva
   `require_session` como su propia capa interna
   (`src/api.rs:387-400`). Confirmado por
   `preflight_options_to_protected_route_does_not_require_session`
   (`tests/cors.rs:266-302`): un `OPTIONS` a `/api/me` sin cookie responde
   `200`/`204` con las cabeceras CORS correctas, nunca `401`.
5. **Una request real sigue exigiendo sesión pase lo que pase el
   `Origin`**: confirmado por
   `get_me_with_allowed_origin_but_without_session_is_still_rejected`
   (`tests/cors.rs:343-356`) → `401` aunque el `Origin` sea el permitido.
6. **Sin fuga de secretos**: `cors_layer`, `Config::front_origin` y
   `AppState::front_origin` no manejan ningún dato de
   `docs/security-scope.md` (token de Google, sesión firmada, credencial de
   `ms-usuarios`, credencial AMQPS). No se agregó ningún `tracing::*` nuevo
   en el camino de CORS (`grep tracing:: src/api.rs src/wiring.rs
   src/config.rs` solo muestra los ya existentes de otras features, sin
   relación con `front_origin`). `debug_does_not_leak_secrets`
   (`src/config.rs:489-503`) sigue en verde.
7. **`docs/conventions.md`**: rustdoc `///` presente en todo ítem público
   nuevo — `Config::front_origin` (`src/config.rs:100-109`),
   `ConfigError::InvalidUrl` (`src/config.rs:144-154`),
   `AppState::front_origin` (`src/api.rs:300-307`),
   `WiringError::InvalidCorsOrigin` (`src/wiring.rs:41-46`). Ningún
   `unwrap()/expect()/panic!()` fuera de `#[cfg(test)] mod tests`
   (`src/config.rs:260` en adelante; nada nuevo en `src/wiring.rs` ni en el
   código de producción de `src/api.rs`). Errores tipados con `thiserror`
   en ambas variantes nuevas. Nombres `snake_case`/`PascalCase` consistentes
   con la tabla de convenciones. Sin `println!`/`dbg!` en `src/`.

## Checkpoints

- C1: [x] — Existen los 4 archivos base y los 4 docs; `./init.sh` termina
  con exit code 0 (verificado de forma independiente, ver arriba).
- C2: [x] — Solo la feature 13 está `in_progress` en `feature_list.json`
  (features 1-12 en `done`, cada una con su revisión aprobada en
  `progress/review_*.md`/`history.md`); `progress/current.md` describe en
  tiempo real la sesión activa (feature 13), sin basura de sesiones
  anteriores.
- C3: [x] — `src/` solo contiene los módulos de `docs/architecture.md`
  (`lib.rs` declara exactamente `api, auth, broker, config, domain,
  realtime, usuarios_client, wiring`, sin módulo nuevo para CORS: vive
  dentro de `api.rs` como indica la capa 7). `tower-http` y `url` en
  `Cargo.toml` llevan comentario explícito justificando cada uno contra la
  feature `cors_for_front`. Nota menor no bloqueante: `url = "2"` queda
  declarada tanto en `[dependencies]` (nueva) como en `[dev-dependencies]`
  (ya existía) — es redundante (las dependencias de `[dependencies]` ya
  están disponibles en tests) pero inocuo, no viola ninguna convención
  documentada ni genera warning de `cargo`/`clippy`. Sin `println!`/`dbg!`,
  sin `unwrap()/panic!()` fuera de test sin justificar. `cargo doc
  --no-deps` sin warnings.
- C4: [x] — `tests/cors.rs` cubre la nueva superficie de IO (router HTTP
  completo con `axum::serve`, mismo patrón que
  `tests/session_middleware_and_me.rs`). `cargo test` → 55/55 en verde;
  `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — Sin archivos sueltos sospechosos (`*.tmp`, no hay `target/`
  fuera de lo que ya ignora `.gitignore`); el repo no es un repositorio git
  (confirmado), así que el ítem de untracked/git se adapta a esta
  verificación de filesystem en su lugar. `progress/history.md` tiene
  entrada completa de la última sesión cerrada (feature 12,
  `post_login_redirect`, `APPROVED`). La feature 13 está correctamente en
  `in_progress` (pendiente de que el `leader` la cierre tras esta
  revisión) — es el estado correcto mientras la revisión está en curso.

## Cambios requeridos

Ninguno.
