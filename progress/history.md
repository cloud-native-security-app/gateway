# Bitácora histórica (append-only)

> Cada vez que se cierra una sesión, su resumen se añade aquí.
> No edites entradas anteriores. Solo añades al final.

---

_Todavía no hay sesiones de implementación. El arnés (`AGENTS.md`,
`feature_list.json`, `docs/`, `CHECKPOINTS.md`, `.claude/agents/`) se
estableció replicando el patrón de `broker`, `nmap-service` y
`user-service`, adaptado al alcance de `gateway` (Rust + axum + lapin: login
OIDC contra Google, proxy hacia `ms-usuarios`, productor/consumidor del
Broker, relay SSE, rate limiting, OpenAPI). Queda documentada en
`docs/architecture.md` una dependencia pendiente real: el origen de
`network_user`/`ssh_credentials_ref`/`has_sudo` requiere una API nueva en
`user-service` que todavía no existe. La primera entrada real de esta
bitácora la añade la sesión que implemente la feature 1 (`scaffolding`)._

---

## 2026-09-18 — Feature 1: scaffolding — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Qué se hizo:** scaffolding inicial del crate Rust `gateway`. Se creó
  `Cargo.toml` (edition 2021) con `tokio` (`rt-multi-thread`, `macros`),
  `axum`, `lapin` (`features = ["rustls"], default-features = false`),
  `tracing`, `tracing-subscriber`, `serde` (`derive`), `serde_json`, y
  `testcontainers` como dev-dependency. `src/lib.rs` declara `pub mod` para
  las 7 capas (`config`, `domain`, `auth`, `usuarios_client`, `broker`,
  `realtime`, `api`), activa `#![deny(missing_docs)]`, y expone `pub async
  fn run()` (solo loguea "starting" vía `tracing`). `src/main.rs` es un
  envoltorio delgado (`#[tokio::main]` + `tracing_subscriber::fmt::init()`
  + `gateway::run().await`). Cada módulo nuevo trae solo su doc-comment
  `//!` de propósito, sin lógica de negocio de features posteriores.
  No se creó `wiring` (capa 8 de `docs/architecture.md`): no está en el
  `acceptance` de la feature 1, se deja para cuando una feature futura lo
  requiera explícitamente.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored`,
  `cargo doc --no-deps` y `./init.sh` — todos verdes, 0 warnings. Detalle
  completo en `progress/impl_scaffolding.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos anteriores (incluyendo `cargo clean -p
  gateway` para descartar caché) y verificar `cargo tree` confirma
  `rustls` en el árbol de `lapin` sin `native-tls`. Sin cambios
  requeridos. Detalle completo en `progress/review_scaffolding.md`.
- **Estado final:** feature 1 (`scaffolding`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-18 — Feature 2: config — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Qué se hizo:** carga y validación de la configuración del servicio
  desde variables de entorno. Se reescribió `src/config.rs`: struct pública
  `Config` con un campo por variable
  (`HTTP_HOST`/`HTTP_PORT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `GOOGLE_REDIRECT_URI`, `SESSION_SIGNING_KEY`, `SESSION_TTL_SECS`,
  `BROKER_AMQPS_URL`, `BROKER_VHOST`, `MS_USUARIOS_BASE_URL`,
  `MS_USUARIOS_SHARED_SECRET`), `Config::from_env() -> Result<Config,
  ConfigError>` sin panics, y `ConfigError` (`thiserror`) con variantes
  `Missing { name }` e `InvalidNumber { name, source }`. Los 4 campos que
  transportan una credencial (`google_client_secret`, `session_signing_key`,
  `broker_amqps_url`, `ms_usuarios_shared_secret`) usan
  `secrecy::SecretString`, que redacta en `Debug` y no implementa `Display`.
  Se añadieron `secrecy = "0.10.3"` y `thiserror = "2.0.20"` a `Cargo.toml`
  (dependencias normales, vía `cargo add`). Ningún valor hardcodeado fuera
  de los nombres de las variables de entorno y los fixtures de laboratorio
  en tests.
- **Verificación:** `cargo build`, `cargo clippy --all-targets -- -D
  warnings`, `cargo fmt --check`, `cargo test` (5 tests en
  `config::tests`, todos verdes) y `./init.sh` — todo en verde, 0 warnings.
  Detalle completo en `progress/impl_config.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación y revisar los 4
  criterios de aceptación uno por uno contra el código línea por línea.
  Sin cambios bloqueantes. Nota no bloqueante documentada: discrepancia de
  nombre entre `docs/security-scope.md` (`GATEWAY_SHARED_SECRET`) y
  `feature_list.json`/código (`MS_USUARIOS_SHARED_SECRET`) para la misma
  credencial de servicio hacia `ms-usuarios`; se siguió el nombre exacto
  del criterio de aceptación de la feature. Queda como nota para una
  sesión futura (relevante sobre todo para la feature `usuarios_profile_proxy`,
  id=5), no bloquea el cierre de esta feature. Detalle completo en
  `progress/review_config.md`.
- **Estado final:** feature 2 (`config`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 3: oidc_login — DONE

- **Agente:** leader (orquestando 3 explorers en paralelo + implementer +
  reviewer).
- **Investigación previa:** 3 explorers en paralelo (`progress/explore_openidconnect.md`,
  `progress/explore_session_cookie.md`, `progress/explore_test_idp.md`)
  confirmaron la API exacta de `openidconnect` 4.0.1
  (`CoreProviderMetadata::discover_async` contra un issuer arbitrario,
  válido para apuntar a Google en producción o a un IdP de prueba en
  tests), `jsonwebtoken` 11.1.0 para la sesión propia, `axum-extra` 0.9.6
  (única versión compatible con `axum = "0.7"` ya fijado) para la cookie,
  y el patrón de IdP de prueba en memoria (axum + `jsonwebtoken::jwk` +
  `rsa`, sin `wiremock`). Se detectó y resolvió con el usuario una
  ambigüedad entre `feature_list.json` y `docs/verification.md` sobre si
  los tests de `auth` con IdP en memoria llevan `#[ignore = "requiere
  Docker"]`: decisión confirmada de que **no** lo llevan (corren en
  `cargo test` normal), documentada en `progress/current.md` antes de
  despachar al implementer.
- **Qué se hizo:** flujo completo de login OIDC delegado en Google.
  `src/config.rs` gana `GOOGLE_OIDC_ISSUER_URL` (opcional, default
  `https://accounts.google.com`, override en tests) — gap detectado por
  el explorer, plumbing necesario para esta feature. `src/domain.rs` gana
  `Session { sub, email, name, exp }`. `src/auth.rs` implementa
  `AuthError` (`thiserror`), `OidcClient` (discovery + `begin_login` con
  PKCE/`state`/`nonce` + `exchange_and_verify` que valida firma
  JWKS/`aud`/`iss`/`exp`/`nonce` y descarta el ID token tras extraer la
  identidad), `LoginStateStore` (store en memoria del `state`→(`nonce`,
  PKCE), TTL de 10 min, uso único — limitación de un solo proceso
  documentada explícitamente), `issue_session_token`/`session_cookie`/
  `removal_cookie`. `src/api.rs` monta `GET /auth/login`,
  `GET /auth/callback`, `POST /auth/logout` sobre un `AppState` propio, y
  traduce `AuthError` a 400/401/500 según el caso (`impl IntoResponse`).
  Nuevas dependencias: `openidconnect`, `jsonwebtoken` (con feature
  `rust_crypto`, requerida en runtime — sin ella `encode`/`decode` entran
  en pánico), `axum-extra` (solo feature `cookie`), `cookie` (dependencia
  directa, ya resuelta transitivamente por `axum-extra`); en dev:
  `rsa`/`rand`/`base64` (IdP de prueba), `reqwest`/`url` (cliente HTTP de
  test). No se tocó el middleware de sesión (diferido a la feature 4,
  `session_middleware_and_me`) ni ninguna otra ruta/módulo fuera de
  alcance.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (12 unit + 8 integración en
  `tests/oidc_login.rs`, todos verdes, ninguno `#[ignore]`), `cargo test
  -- --ignored` (0 tests, no aplica todavía), `cargo doc --no-deps` y
  `./init.sh` — todo en verde, 0 warnings. Los 8 tests de integración
  levantan un IdP OIDC de prueba en memoria (discovery + JWKS + `/token`
  propios, `axum::serve` sobre puerto efímero) y ejercen el router real de
  `gateway::api`: login redirige con los parámetros correctos; callback
  válido crea sesión (cookie `HttpOnly`+`Secure`+`SameSite=Strict`
  verificada, JWT decodificado y comparado campo a campo); callback
  rechaza audiencia incorrecta/expirado/firma inválida (3 tests, 401, sin
  `Set-Cookie`); `state` ausente/no coincidente rechazado (2 tests, 400);
  logout borra la cookie (204, `Max-Age=0`/`Expires` pasado). Detalle
  completo en `progress/impl_oidc_login.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente `cargo build`/`fmt`/`clippy`/`test`/`test -- --ignored`/
  `doc`/`./init.sh`, y verificar los 7 criterios de aceptación uno por uno
  contra el código y los tests (líneas concretas citadas). Confirmó que el
  ID token de Google nunca se loggea/persiste/reenvía (`grep -rn
  "tracing::" src/` solo devuelve el `Display` genérico de `AuthError`),
  que no se adelantó ningún trabajo de la feature 4 (sin función de
  validación de sesión reutilizable fuera de tests), y que `src/config.rs`
  no reabrió nada de la feature 2 ya `done`. Sin cambios requeridos.
  Detalle completo en `progress/review_oidc_login.md`.
- **Estado final:** feature 3 (`oidc_login`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 4: session_middleware_and_me — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  complejidad media, reutiliza `jsonwebtoken` ya integrado en la feature 3).
- **Qué se hizo:** middleware `axum` que exige sesión propia válida en toda
  ruta protegida (RNF-02), y `GET /api/me`. `src/auth.rs` gana
  `AuthError::SessionInvalid` (401 genérico, sin filtrar el motivo exacto
  al cliente), `SessionValidator` (`new`/`validate`: decodifica y valida el
  JWT de sesión — firma HS256, `exp`, `aud`, `iss` — reutilizando el mismo
  `SessionClaims` que ya usaba `issue_session_token`) y `require_session`
  (middleware compatible con `axum::middleware::from_fn_with_state`: sin
  cookie o inválida → `401` sin ejecutar el handler; válida → inserta
  `Session` en `request.extensions_mut()`). `src/api.rs` gana
  `health_router`/`GET /health` (pública, sin lógica de negocio),
  `protected_router` (privado, monta `GET /api/me` con `.layer(...)` de
  `require_session`), el handler `me` + `MeResponse` (solo
  `sub`/`email`/`name`, sin tocar `ms-usuarios`), la tabla canónica
  `pub const ROUTES` (método/path/`protected: bool`, fuente única de verdad
  para el test de enumeración — axum 0.7 no expone introspección real del
  router) y `pub fn app_router` que mergea `auth_router` (login/callback/
  logout, público) + `health_router` (público) + `protected_router`
  (con middleware). Se decidió mantener `/auth/logout` **pública** (fuera
  del middleware): el logout es una acción puramente del navegador (borra
  la cookie), exigir sesión válida para cerrarla crearía sesiones
  "atascadas" para cookies ya vencidas/corruptas, y protegerla habría roto
  el test ya aprobado `logout_clears_the_session_cookie` de la feature 3.
  Nuevo archivo `tests/session_middleware_and_me.rs` (mismo patrón que
  `tests/oidc_login.rs`: router real servido con `axum::serve` sobre
  puerto efímero, sin Docker).
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (16 unitarios + 8
  `tests/oidc_login.rs` sin regresión + 5 `tests/session_middleware_and_me.rs`
  nuevos = 29 tests verdes), `cargo doc --no-deps` y `./init.sh` — todo en
  verde, 0 warnings. Detalle completo en
  `progress/impl_session_middleware_and_me.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación y validar los 5
  criterios de aceptación uno por uno contra el código y los tests (líneas
  concretas citadas). Confirmó la decisión de dejar `/auth/logout` pública
  (duda documentada por el implementer), con justificación adicional en
  `docs/security-scope.md`. Observación no bloqueante: el test de
  enumeración de rutas verifica comportamiento HTTP contra una tabla
  mantenida a mano (`ROUTES`), no introspección estructural real del
  router — mitigado porque la protección real se aplica vía `.layer()` a
  nivel de sub-router, no depende de `ROUTES`; recomendación para
  features futuras de acoplar ambas cosas, no bloqueante. Sin cambios
  requeridos. Detalle completo en
  `progress/review_session_middleware_and_me.md`.
- **Estado final:** feature 4 (`session_middleware_and_me`) pasó a
  `"done"` en `feature_list.json`.
