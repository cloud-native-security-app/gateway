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

---

## 2026-09-19 — Feature 5: usuarios_profile_proxy — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  `reqwest` ya presente como dev-dependency con `rustls-tls`, sin crates ni
  API desconocida).
- **Qué se hizo:** único módulo que conoce la URL y el contrato HTTP de
  `ms-usuarios`. `Cargo.toml` promueve `reqwest` de `dev-dependencies` a
  `dependencies` (mismas features `rustls-tls`, sin `native-tls`, más
  `json` para simplificar el (de)serializado). `src/usuarios_client.rs`
  (antes vacío) implementa `UsuariosClient::{new, get_profile,
  upsert_profile}` (`GET`/`PUT /users/me`), reenviando en cada llamada un
  header de identidad `X-Gateway-Identity` (JSON `{"sub","email"}`, nunca
  el JWT de sesión completo ni el token de Google) y la credencial de
  servicio `MS_USUARIOS_SHARED_SECRET` en `X-Gateway-Service-Secret`; y
  `UsuariosClientError` (`thiserror`: `Unreachable`, `UnexpectedResponse`,
  `MalformedResponse`, `RequestBuild`), ninguna variante expone la URL base
  ni la credencial. Como el contrato real de `user-service/docs` no está
  disponible en este checkout, el perfil se trata como JSON opaco
  (`UserProfile = serde_json::Value`, reenviado tal cual en vez de inventar
  campos) — decisión documentada explícitamente como suposición a
  confirmar, no como contrato cerrado. `src/api.rs` gana
  `AppState::usuarios_client`, la ruta `GET /api/profile` (protegida,
  dentro de `protected_router`, listada en `ROUTES`) y
  `impl IntoResponse for UsuariosClientError`
  (`Unreachable→504`, `UnexpectedResponse`/`MalformedResponse→502`,
  `RequestBuild→500`). `tests/oidc_login.rs` y
  `tests/session_middleware_and_me.rs` se actualizaron solo para pasar un
  `UsuariosClient` de laboratorio al nuevo campo obligatorio de `AppState`,
  sin tocar su lógica.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (19 unitarios lib + 8
  `oidc_login` + 5 `session_middleware_and_me` + 6 `usuarios_client` nuevos
  + 3 `usuarios_profile_proxy` nuevos = 41 tests verdes, ninguna feature
  1-4 se rompió), `cargo doc --no-deps` y `./init.sh` — todo en verde, 0
  warnings. Ningún test de esta feature está `#[ignore]` (no depende de
  Docker: servidor HTTP de test real en puerto efímero, mismo patrón que
  `oidc_login`). Detalle completo en
  `progress/impl_usuarios_profile_proxy.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación y validar los 5
  criterios de aceptación uno por uno contra el código y los tests (líneas
  concretas citadas), con `grep` propio para confirmar que ningún otro
  módulo hace HTTP directo hacia `ms-usuarios`, que la credencial de
  servicio nunca se loggea, y que no hay `unwrap`/`expect`/`panic!` fuera
  de tests en el código nuevo. Confirmó explícitamente que las suposiciones
  sobre el contrato de `ms-usuarios` (nombres de header, shape de perfil
  como JSON opaco) están marcadas como suposición a confirmar y no como
  contrato cerrado, coherente con `docs/architecture.md` §"Qué NO hacer".
  Sin cambios requeridos. Detalle completo en
  `progress/review_usuarios_profile_proxy.md`.
- **Estado final:** feature 5 (`usuarios_profile_proxy`) pasó a `"done"` en
  `feature_list.json`.

## Corrección post-feature-5: nombres reales de header hacia ms-usuarios (2026-09-19)

- **Hallazgo:** investigando el contrato real de `ms-usuarios` para preparar
  la feature 6 (leyendo el repo hermano `user-service/src/api.rs`, de solo
  lectura), se confirmó que los headers reales son `X-Gateway-Secret`
  (credencial de servicio) y `X-Forwarded-User` (identidad) — distintos de
  `X-Gateway-Identity`/`X-Gateway-Service-Secret` que la feature 5
  (`usuarios_profile_proxy`) había implementado como suposición documentada
  (aprobada en su momento porque el contrato no era verificable).
- También se confirmó que la ruta `GET/PUT /users/me` sí coincidía con lo
  asumido, y que `user-service` ya expone `POST /users/me/scans` (body
  `{target}` -> `ScanHistoryEntry` con `status: Pendiente`) y
  `PATCH /scans/{scan_id}` (body `{status}` -> 204), endpoints que la
  feature 6 necesitará para el histórico. El vacío de diseño de
  `network_user`/`ssh_credentials_ref`/`has_sudo` sigue sin resolver en
  `user-service` — la feature 6 debe seguir el camino de error explícito
  501/422 ya previsto en `docs/architecture.md`.
- **Decisión del usuario:** corregir el fix antes de empezar la feature 6.
- **Fix:** `src/usuarios_client.rs` y sus tests renombrados a los headers
  reales, cambio mínimo y mecánico (confirmado por el reviewer vía grep:
  cero referencias a los nombres viejos en todo el repo). `feature_list.json`
  no se tocó (feature 5 sigue `"done"`, sus criterios de aceptación
  formales seguían cumpliéndose). `./init.sh` en verde, 41 tests.
  Detalle en `progress/impl_fix_usuarios_client_headers.md` y
  `progress/review_fix_usuarios_client_headers.md`.

---

## 2026-09-19 — Feature 6: scan_submission — DONE

- **Agente:** leader (orquestando 2 explorers en paralelo + implementer +
  reviewer).
- **Investigación previa:** el leader confirmó directamente (sin subagente,
  leyendo los repos hermanos de solo lectura) el shape exacto de
  `ScanRequest` (`broker/contracts/scan-request.schema.json`:
  `correlation_id`/`ip`/`network_user`/`ssh_credentials_ref`/`has_sudo`/
  `requested_by`, todos requeridos, `additionalProperties: false`), la
  topología real (`broker/rabbitmq/definitions.json`: usuario `gateway` con
  `write` solo en `scan.requests`/`scan.cancellations`), y el contrato real
  de `user-service` (`POST /users/me/scans`/`PATCH /scans/{scan_id}` ya
  existen; el endpoint para resolver `network_user`/`ssh_credentials_ref`/
  `has_sudo` sigue sin existir). Se despacharon 2 explorers en paralelo
  para la complejidad de Broker/AMQPS:
  `progress/explore_lapin_publish.md` (hallazgo crítico: `gateway` fija
  `lapin 2.5.5`, no 4.x como `broker/` — API de conexión distinta,
  verificada contra el código fuente real; trade-off de `confirm_select`
  vs RNF-04) y `progress/explore_lapin_testcontainers.md`
  (`rabbitmq:4.3.5-management` vía `testcontainers::GenericImage` 0.20.1,
  copia literal de la topología/TLS de `broker/`, cola de verificación
  declarada con `lab-admin` porque `gateway` no tiene permiso `configure`).
- **Qué se hizo:** `POST /api/scans` (ruta protegida). `src/domain.rs` gana
  `ScanSubmission`/`ScanSubmissionError` (validación pura de IP/CIDR,
  RF-02/RF-03). `src/broker.rs` (antes stub vacío) implementa `ScanRequest`
  (shape copiado literal del schema, `Debug` manual que redacta
  `ssh_credentials_ref`), `BrokerError` (`thiserror`), el trait
  `ScanRequestPublisher` (`async_trait`, para poder inyectar un doble de
  prueba en `AppState` sin abrir una conexión AMQPS real en tests de otras
  features) y `BrokerPublisher` (conexión+canal `lapin` 2.5.5 persistentes,
  `confirm_select` activado una sola vez, sin declarar topología). Se
  decidió esperar el ack/nack real del Broker en el hot path (no solo el
  envío del frame): RNF-04 permite 500ms y un ack en subred privada añade
  típicamente un dígito de milisegundos, y es la única forma de distinguir
  "se publicó" de "se envió el frame pero se rechazó" — necesario para el
  criterio de marcar `Fallido`. `src/usuarios_client.rs` gana `ScanStatus`
  (confirmado contra `user-service/src/domain.rs`, `SCREAMING_SNAKE_CASE`),
  `ScanHistoryEntry` (contrato real), `ScanTargetCredentials` (contrato
  **especulativo**, documentado explícitamente como tal), y los métodos
  `create_scan_history`/`update_scan_status`/`resolve_scan_target`. Un
  `404` de `ms-usuarios` en `resolve_scan_target` (la API no existe
  todavía) se traduce a `501`; un `422` (existe pero sin credenciales) a
  `422` — nunca un valor inventado. `src/api.rs` gana
  `AppState::broker_publisher` (`Arc<dyn ScanRequestPublisher>`) y el
  handler `submit_scan`: valida antes de cualquier llamada externa, genera
  su propio `scanId` (`uuid` v4) antes de la primera llamada externa,
  intenta resolver credenciales, registra histórico y publica; si el
  publish falla tras registrar histórico, marca `Fallido` (best-effort,
  loggeado si esa compensación también falla) y reporta el error, nunca
  deja un `Pendiente` huérfano. **Decisión de diseño documentada
  explícitamente** (evaluada y aceptada por el reviewer): como
  `POST /users/me/scans` de `user-service` no acepta un `scan_id` externo
  (lo genera internamente), el `scanId` propio de Gateway y el `scan_id`
  real de `ms-usuarios` son dos identificadores distintos — el primero es
  el `correlation_id` del `ScanRequest` y el que se devuelve al cliente, el
  segundo se usa solo para la compensación a `Fallido`. Queda anotado para
  que la feature futura `scan_outcome_relay` no asuma que son el mismo
  valor. Nuevo archivo `tests/scan_submission.rs` (4 tests: 3 sin Docker —
  inválido→400, API de credenciales ausente→501, sin credenciales
  configuradas→422 — y 1 `#[ignore = "requiere Docker"]` con el camino
  feliz contra RabbitMQ real). Nuevos fixtures `rabbitmq/definitions.json`,
  `rabbitmq/rabbitmq.conf`, `rabbitmq/tls/*.pem`, copia literal de
  `broker/rabbitmq/` (sin `ca_key.pem`, no usado por ningún test). Nuevas
  dependencias: `tokio-executor-trait`/`tokio-reactor-trait` (runtime de
  `lapin` sobre `tokio`), `async-trait`, `uuid`; en dev: `rustls`
  (instalación defensiva del proveedor criptográfico),
  `futures-util` (`.next()` sobre el consumidor de `lapin` en tests).
  `tests/oidc_login.rs`/`tests/session_middleware_and_me.rs`/
  `tests/usuarios_profile_proxy.rs` actualizados mecánicamente para el
  nuevo campo `AppState::broker_publisher` (doble de prueba que hace
  `panic!` si se invoca, ya que esas features no ejercen `POST /api/scans`).
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (38 unitarios + 25 de
  integración sin Docker en verde, ninguna feature 1-5 se rompió),
  `cargo test -- --ignored` (Docker disponible: el camino feliz pasa
  contra `rabbitmq:4.3.5-management` real, sin contenedores huérfanos tras
  la corrida), `cargo doc --no-deps` y `./init.sh` — todo en verde, 0
  warnings. Detalle completo en `progress/impl_scan_submission.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación, validar los 7
  criterios de aceptación uno por uno contra el código/tests (líneas
  concretas citadas), confirmar por `grep` que `ssh_credentials_ref` y la
  credencial AMQPS nunca se loggean, que `src/broker.rs` no redeclara
  topología de producción (`grep` sin resultados para
  `exchange_declare`/`queue_declare`/`queue_bind` fuera de
  `tests/scan_submission.rs`), y que la topología de test coincide byte a
  byte (`diff`) con `broker/rabbitmq/`. Evaluó explícitamente la decisión
  de los dos identificadores contra el contrato real de `user-service`
  (confirmado leyendo `user-service/src/api.rs` directamente) y la
  consideró razonable y bien documentada, sin necesidad de bloquear para
  preguntar al usuario. Único hueco no bloqueante señalado: no hay test de
  integración dedicado para la rama "publish falla tras histórico ya
  registrado → Fallido" (no exigido explícitamente por el criterio de
  aceptación #7, que solo enumera 3 escenarios). Sin cambios requeridos.
  Detalle completo en `progress/review_scan_submission.md`.
- **Estado final:** feature 6 (`scan_submission`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 7: scan_outcome_relay — DONE

- **Agente:** leader (orquestando 2 explorers en paralelo + implementer +
  reviewer).
- **Investigación previa:** el leader confirmó directamente (sin
  subagente, leyendo repos hermanos de solo lectura) el shape exacto de
  `ScanOutcome` (`broker/contracts/scan-outcome.schema.json`: 3 variantes
  `started`/`completed`/`failed` discriminadas por `status`, todas con
  `correlation_id` — el `scanId` propio de Gateway generado en la feature
  6, no un identificador nuevo) y detectó un problema de diseño heredado
  de la feature 6: `PATCH /scans/{scan_id}` de `ms-usuarios` exige SU
  PROPIO `scan_id`, distinto del `correlation_id`. Resuelto con el usuario:
  registro en memoria en `AppState`, poblado por `submit_scan` (feature 6,
  ya cerrada, extendida sin reabrirse) y consultado por esta feature. Se
  despacharon 2 explorers en paralelo:
  `progress/explore_lapin_consume.md` (API de consumo de `lapin` 2.5.5:
  `basic_consume`/`Consumer` como `Stream`/`Acker::ack`/`nack`; sin
  reconexión automática por diseño; mensaje malformado ->
  `nack(requeue=false)`, justificado contra el comportamiento real de
  `x-delivery-limit`; no hace falta declarar cola/binding, topología y
  permisos ya existen) y `progress/explore_sse.md` (`axum::response::sse`
  0.7.9, diseño de `RealtimeRegistry` con `broadcast::Sender` tras
  `RwLock`, cierre de stream con `stream::unfold`, patrón de test SSE con
  `reqwest::bytes_stream()`; 2 gotchas de dependencias corregidos y aviso
  crítico de sintaxis de ruta `:scan_id` en axum 0.7, no `{scan_id}`).
- **Qué se hizo:** consumo de `gateway.scan-outcomes` y relay en tiempo
  real vía SSE (RF-07/RF-08). `src/domain.rs` gana `ScanOutcomeEvent`
  (enum `Started`/`Completed`/`Failed`, tag `status`,
  `deny_unknown_fields`, copiado literal del schema real) y
  `ScanResult`/`PortFinding`/`VulnFinding`. `src/broker.rs` gana
  `BrokerConsumer` (conexión/canal `lapin` dedicados, reutilizando la
  lógica de conexión AMQPS ya factorizada junto a `BrokerPublisher`) y el
  trait `ScanOutcomeHandler`: `run()` consume la cola sin declarar
  topología (coherente con `configure: "^$"` del usuario `gateway`), hace
  `ack` en cuanto decodifica con éxito (antes de invocar al handler, para
  que un fallo downstream nunca bloquee el ack) y `nack(requeue: false)`
  en mensaje malformado (log sin payload crudo: solo el error de
  deserialización, `routing_key`, tamaño en bytes). `src/realtime.rs` gana
  `RealtimeRegistry` (`HashMap<scan_id, broadcast::Sender>` tras `RwLock`,
  `subscribe_stream` construido con `stream::unfold` que cierra
  ordenadamente al emitir un evento terminal, `SubscriptionGuard` con
  `Drop` para limpiar el registro tanto en cierre ordenado como en
  desconexión temprana del cliente). `src/api.rs` gana
  `ScanOwnershipRegistry`/`ScanOwnership` (registro en memoria acordado
  con el usuario: `scanId` propio -> `{ms_usuarios_scan_id, owner:
  Session}`, mismo patrón/limitación que `auth::LoginStateStore`),
  `AppState::scan_ownership`/`AppState::realtime`, la ruta
  `GET /api/scans/:scan_id/events` (protegida, sintaxis axum 0.7) con
  autorización estricta por sesión dueña (404 idéntico para scan_id
  ausente o ajeno, nunca revela si existe), y **una única línea añadida**
  a `submit_scan` (feature 6, ya aprobada, no reabierta) que registra la
  propiedad justo después de `create_scan_history`. Como ninguna feature
  anterior había necesitado un proceso realmente en marcha (todas
  probaban su router a mano), esta feature materializó por primera vez la
  capa `wiring` ya prevista (pero diferida) en `docs/architecture.md`:
  `src/wiring.rs` (nuevo) construye `OidcClient`/`UsuariosClient`/
  `BrokerPublisher`/`BrokerConsumer`/`ScanOwnershipRegistry`/
  `RealtimeRegistry` y el `ScanOutcomeRelay` (puente privado que ata el
  consumidor a `ms-usuarios` + SSE, best-effort); `src/lib.rs::run()` pasó
  de un stub a un arranque real (`Config::from_env` -> `wiring::build` ->
  `tokio::spawn` del consumidor de fondo -> `axum::serve`), con `RunError`
  tipado y `main.rs` loggeando y saliendo con código 1 en caso de fallo,
  sin panics. Nuevo archivo `tests/scan_outcome_relay.rs` (2 tests sin
  Docker para el rechazo de `scan_id` ajeno/inexistente + 1
  `#[ignore = "requiere Docker"]` que publica manualmente
  `started`/malformado/`completed` en la cola real, verifica el stream SSE
  en orden con cierre tras el evento terminal, y confirma que `ms-usuarios`
  recibe `EN_PROGRESO`/`COMPLETADO` en orden). `Cargo.toml`: `futures-util`
  promovida a `[dependencies]` (ya usada en producción), `tokio` con
  feature `sync` explícito, `reqwest`+`bytes` añadidos a
  `[dev-dependencies]` para `bytes_stream()` en el test SSE.
  `tests/oidc_login.rs`/`tests/session_middleware_and_me.rs`/
  `tests/usuarios_profile_proxy.rs`/`tests/scan_submission.rs`
  actualizados mecánicamente para los 2 campos nuevos de `AppState`.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (47 unitarios + 27 de
  integración sin Docker en verde, ninguna feature 1-6 se rompió),
  `cargo test -- --ignored` (Docker disponible: ambos tests Docker —el
  nuevo de esta feature y el ya existente de `scan_submission`— pasan, sin
  contenedores huérfanos), `cargo doc --no-deps` y `./init.sh` — todo en
  verde, 0 warnings. Detalle completo en
  `progress/impl_scan_outcome_relay.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el test
  Docker), validar los 6 criterios de aceptación uno por uno contra el
  código/tests (líneas concretas citadas), confirmar por `git diff` que el
  único cambio dentro de `submit_scan` (feature 6) es la inserción de 3
  líneas sin alterar el resto de su lógica ya aprobada, y confirmar que
  ningún log nuevo incluye la credencial AMQPS, `ssh_credentials_ref`, la
  credencial de servicio hacia `ms-usuarios`, ni la sesión firmada
  completa. Evaluó explícitamente la expansión hacia `wiring`/`run()` real
  (antes un stub) y la consideró proporcional y necesaria, no una
  expansión de alcance injustificada: la capa `wiring` ya estaba prevista
  en `docs/architecture.md` y diferida explícitamente por la feature 1
  "para cuando una feature futura lo requiera explícitamente" — esta es
  esa feature (primera con una tarea de fondo que debe vivir todo el ciclo
  de vida del proceso). Sin cambios requeridos. Detalle completo en
  `progress/review_scan_outcome_relay.md`.
- **Estado final:** feature 7 (`scan_outcome_relay`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 8: scan_history_and_cancellation — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers: el
  leader confirmó directamente, leyendo repos hermanos de solo lectura, el
  shape de `ScanCancellation` y el contrato real de `GET /users/me/scans`
  antes de despachar).
- **Investigación previa:** el leader confirmó
  `broker/contracts/scan-cancellation.schema.json` (`{correlation_id,
  requested_by}`, ambos `string`, `additionalProperties: false`;
  `correlation_id` es explícitamente el del `ScanRequest` a cancelar, o sea
  el `scanId` propio de Gateway, nunca el `scan_id` de `ms-usuarios`) y que
  el usuario RabbitMQ `gateway` ya tenía `write` sobre `scan.cancellations`
  desde la topología copiada en la feature 6. Detectó que `GET /api/scans`
  necesitaría exponer ese `scanId` propio por entrada para que el cliente
  pueda cancelar/reabrir SSE con el mismo id, lo que exige un lookup inverso
  nuevo en `ScanOwnershipRegistry` (feature 7): decisión acordada con el
  usuario de añadir `lookup_by_ms_usuarios_scan_id` (recorrido lineal,
  documentado, sin segundo índice) y de que el campo `scanId` sea opcional
  (ausente si no hay mapeo conocido, misma limitación ya documentada de
  "memoria de proceso, no persistente").
- **Qué se hizo:** `GET /api/scans` (histórico, RF-13) y
  `POST /api/scans/{scan_id}/cancel` (cancelación, RF-14).
  `src/usuarios_client.rs` gana `list_scan_history` (`GET
  /users/me/scans`, mismo endpoint de colección que ya usaba
  `create_scan_history` con otro verbo, contrato confirmado real contra
  `user-service/src/api.rs`). `src/broker.rs` gana `ScanCancellation`
  (shape copiado literal del schema), las constantes
  `EXCHANGE_SCAN_CANCELLATIONS`/`ROUTING_KEY_SCAN_CANCELLATION`, y
  `publish_scan_cancellation` añadido al trait `ScanRequestPublisher` ya
  existente (decisión explícita: extender el trait en vez de crear uno
  hermano, porque ambos métodos comparten la misma conexión/canal/usuario
  RabbitMQ y separar habría exigido un segundo campo en `AppState` sin
  beneficio real); se extrajo un helper privado `publish_and_confirm` en
  `BrokerPublisher` para no duplicar la lógica de serializar+publicar+ack
  entre ambos métodos. `src/api.rs` gana
  `ScanOwnershipRegistry::lookup_by_ms_usuarios_scan_id` (lookup inverso),
  el handler `list_scan_history` (`GET /api/scans`, traduce cada entrada a
  `ScanHistoryEntryResponse` con `scanId` propio opcional, sin exponer el
  `scan_id` interno de `ms-usuarios` a `front`, RF-09) y el handler
  `cancel_scan` (`POST /api/scans/:scan_id/cancel`, sintaxis axum 0.7):
  verifica ownership igual que `scan_events` de la feature 7 (404 uniforme
  para scan ajeno o inexistente), consulta `list_scan_history` para conocer
  el estado actual del `scan_id` de `ms-usuarios` antes de decidir si
  publicar (decisión documentada: preferir consultar a `ms-usuarios`, la
  fuente de verdad ya actualizada por el relay de la feature 7, en vez de
  duplicar estado local que podría desincronizarse), responde `409` sin
  publicar si el estado ya es `Completado`/`Fallido`, y en cualquier otro
  caso publica el `ScanCancellation` (`correlation_id` = `scan_id` del
  path, `requested_by` = `sub` de la sesión activa, nunca un identificador
  reenviado sin verificar) y responde `202 Accepted`. Nuevas entradas en
  `ROUTES` (`GET /api/scans`, `POST /api/scans/:scan_id/cancel`, ambas
  protegidas), cubiertas automáticamente por el test de enumeración de
  rutas de la feature 4 sin cambios en ese test. Los 5 dobles de prueba
  `NeverPublishesToBroker` de `tests/oidc_login.rs`,
  `tests/session_middleware_and_me.rs`, `tests/usuarios_profile_proxy.rs`,
  `tests/scan_submission.rs` y `tests/scan_outcome_relay.rs` se actualizaron
  para implementar también `publish_scan_cancellation` (panicking, mismo
  patrón ya usado para `publish_scan_request`), porque el trait extendido
  lo exige. Nuevo archivo `tests/scan_history_and_cancellation.rs` (5 tests:
  4 sin Docker — histórico con/sin `scanId` conocido, cancelación de scan
  ajeno, cancelación de scan inexistente, cancelación de scan ya terminado
  sin publicar — y 1 `#[ignore = "requiere Docker"]` con el camino feliz de
  cancelación contra RabbitMQ real, verificando el mensaje consumido de una
  cola bindeada a `scan.cancellations`/`scan.cancellation`). 2 tests nuevos
  en `tests/usuarios_client.rs` para `list_scan_history` (camino feliz +
  `ms-usuarios` caído).
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (48 unitarios + tests de
  integración sin Docker de las features 1-8, todos verdes, ninguna feature
  anterior se rompió), `cargo test -- --ignored` (Docker disponible: 4
  tests con RabbitMQ real, incluido el nuevo de esta feature, todos verdes,
  sin contenedores huérfanos), `cargo doc --no-deps` y `./init.sh` — todo en
  verde, 0 warnings. Detalle completo en
  `progress/impl_scan_history_and_cancellation.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el test
  Docker), validar los 5 criterios de aceptación uno por uno contra el
  código/tests, confirmar leyendo `user-service/src/api.rs` que `GET
  /users/me/scans` (handler `list_scans`) es un endpoint real, no
  inventado, confirmar que el usuario RabbitMQ `gateway` sí tiene `write`
  sobre `scan.cancellations` en `broker/rabbitmq/definitions.json`, y
  confirmar por `grep` que `update_scan_status` sigue invocándose solo
  desde `submit_scan` (feature 6) y que `cancel_scan` nunca lo duplica.
  Evaluó las 3 decisiones de diseño (extender el trait en vez de uno
  hermano, lookup inverso lineal, consultar `ms-usuarios` en vez de estado
  local) como razonables y bien documentadas. Confirmó que ningún log o
  cuerpo de error expone credenciales, y que `requested_by` siempre es la
  identidad de sesión ya verificada. Sin cambios requeridos. Detalle
  completo en `progress/review_scan_history_and_cancellation.md`.
- **Estado final:** feature 8 (`scan_history_and_cancellation`) pasó a
  `"done"` en `feature_list.json`.

---

## 2026-09-19 — Feature 9: rate_limiting — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  complejidad media, middleware nuevo sobre `POST /api/scans` ya existente,
  sin Broker/OIDC/SSE).
- **Investigación previa:** el leader verificó que `tower_governor 0.8.0`
  resuelve sin conflicto contra `axum = "0.7"` ya fijado (`cargo add
  --dry-run` limpio). El criterio de aceptación menciona esa crate solo como
  ejemplo ("p. ej."), no como obligación, así que se dejó al implementer
  decidir entre ella (con un `KeyExtractor` propio) o un limitador propio en
  memoria, documentando la elección.
- **Qué se hizo:** límite de tasa por usuario (RF-12) sobre `POST
  /api/scans`. Tras investigar la API de `KeyExtractor` de `tower_governor`,
  el implementer optó por un limitador propio en memoria
  (`ScanSubmissionRateLimiter` en `src/api.rs`: `Mutex<HashMap<sub,
  RateLimitWindow>>`, ventana fija reiniciada al expirar), mismo patrón ya
  usado dos veces en el repo (`auth::LoginStateStore`,
  `ScanOwnershipRegistry`) — evita añadir una dependencia nueva y el mismo
  problema de orden de capas que `tower_governor` habría exigido resolver
  igual. `src/config.rs` gana `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS`
  (u32) y `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS` (u64), sin hardcode.
  `src/wiring.rs` construye el limitador real desde `Config`. `src/api.rs`
  gana `RateLimitError` (`thiserror`, -> `429` con mensaje explícito) y el
  middleware `rate_limit_scan_submission`, que lee `Extension<Session>`
  (nunca la IP) y se aplica **solo** al método `POST` de `/api/scans`
  (`post(submit_scan).layer(...)` construido antes de encadenar
  `.get(list_scan_history)`, verificado contra el código fuente real de
  `axum` 0.7.9: `MethodRouter::layer` solo envuelve los métodos ya
  configurados en ese momento), anidado dentro de la capa de sesión que ya
  cubre todo `protected_router`, de modo que se ejecuta después de
  `auth::require_session` y antes de cualquier llamada a `ms-usuarios`/el
  Broker. Nuevo archivo `tests/rate_limiting.rs` (3 tests de integración
  sin Docker: usuario que excede el umbral recibe `429` en la solicitud que
  lo supera; un segundo usuario en paralelo con contador independiente
  sigue recibiendo `200`; una solicitud rechazada con umbral 0 nunca llega
  a tocar un `ms-usuarios` inalcanzable ni un publicador del Broker que
  hace `panic!` si se invoca) más 4 unit tests en `src/api.rs` (umbral
  respetado, rechazo al superarlo, contadores independientes,
  reinicio tras expirar la ventana). Los 6 archivos de test existentes que
  construyen `AppState` a mano se actualizaron mecánicamente para el nuevo
  campo obligatorio `scan_submission_rate_limiter` (umbral alto, 1000/60s,
  que no interfiere con sus propios escenarios).
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (54 unitarios + todos los
  tests de integración sin Docker en verde, ninguna feature 1-8 se rompió),
  `cargo test -- --ignored` (Docker disponible: los 3 tests existentes con
  RabbitMQ real siguen en verde), `cargo doc --no-deps` y `./init.sh` —
  todo en verde, 0 warnings. Detalle completo en
  `progress/impl_rate_limiting.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación, validar los 5 criterios
  de aceptación uno por uno contra el código/tests (líneas concretas
  citadas), y evaluar explícitamente la decisión de usar un limitador
  propio en vez de `tower_governor` (razonable, verificable, consistente
  con `docs/conventions.md` "homogeneidad extrema", y no una violación de
  `docs/architecture.md` porque el criterio de aceptación deja la crate
  como ejemplo, no como obligación). Confirmó que no hay filtración de
  `sub`/credenciales en logs, que `RateLimitError` y el resto del código
  nuevo siguen el patrón `thiserror` del repo, y que la tabla `ROUTES`/su
  test de enumeración no cambiaron (ninguna ruta cambió su estado
  protegido/público por accidente). Sin cambios requeridos. Detalle
  completo en `progress/review_rate_limiting.md`.
- **Estado final:** feature 9 (`rate_limiting`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 10: openapi_docs — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers: el
  leader verificó directamente, vía `cargo add --dry-run`, que `utoipa
  5.5.0` (features `axum_extras`, `macros`) resuelve sin conflicto contra
  `axum = "0.7"` ya fijado, y enumeró de antemano las 10 rutas públicas
  existentes a documentar).
- **Qué se hizo:** especificación OpenAPI de toda ruta pública de este
  Gateway (RNF-08), generada desde el propio código. `Cargo.toml` gana
  `utoipa = { version = "5.5.0", features = ["axum_extras"] }` (sin
  `utoipa-swagger-ui`: el criterio de aceptación solo exige servir el JSON,
  no una UI interactiva — decisión documentada para evitar una dependencia
  no pedida). `src/api.rs` gana `#[utoipa::path(...)]` sobre los 10
  handlers ya existentes (`login`, `callback`, `logout`, `health`, `me`,
  `profile`, `submit_scan`, `list_scan_history`, `scan_events`,
  `cancel_scan`), reutilizando sus doc-comments `///` ya existentes como
  `summary`/`description` (utoipa los toma automáticamente de rustdoc, sin
  duplicar texto), `#[derive(utoipa::ToSchema)]` en `MeResponse`,
  `ScanSubmissionRequest`, `ScanSubmissionResponse`, `ScanHistoryEntryResponse`
  (y `usuarios_client::ScanStatus`, que aparece como uno de sus campos),
  `#[derive(utoipa::IntoParams)]` en `CallbackParams`, una nueva ruta
  pública `GET /api/openapi.json` (`openapi_router`/`openapi_json`,
  mergeada en `app_router` fuera del middleware de sesión — mismo patrón
  que `health_router` — con su entrada `protected: false` en `ROUTES`), el
  esquema de seguridad `session_cookie` (`impl utoipa::Modify`, referencia
  la cookie `gateway::auth::SESSION_COOKIE_NAME` sin exponer su valor/firma)
  y el agregador `ApiDoc` (`#[derive(utoipa::OpenApi)]` con los 11
  `paths(...)`, `components(schemas(...))` y 5 `tags`). El stream SSE de
  `GET /api/scans/{scan_id}/events` se documenta con la limitación explícita
  de que `utoipa` no modela un body estructurado por evento (se aproxima
  como `text/event-stream` de tipo `string`). Nuevo archivo
  `tests/openapi_docs.rs`: mecanismo anti-drift que traduce la sintaxis de
  parámetro de `axum` (`:scan_id`) a la de OpenAPI (`{scan_id}`) y compara
  el conjunto exacto de paths/métodos de `gateway::api::ROUTES` (la misma
  tabla canónica de la feature 4) contra `ApiDoc::openapi()` serializada a
  JSON y vuelta a parsear (lo mismo que vería un cliente real de
  `GET /api/openapi.json`) — una ruta añadida a `ROUTES` sin anotar/registrar
  en `ApiDoc` hace fallar el `assert_eq!` de conjuntos, verificado
  manualmente por el implementer insertando una ruta falsa y confirmando el
  fallo antes de revertir. Corrección post-revisión (no bloqueante):
  añadida la respuesta `504` (ya presente en los endpoints hermanos
  `GET /api/profile`/`GET /api/scans`) a los `#[utoipa::path]` de
  `POST /api/scans` y `POST /api/scans/{scan_id}/cancel`, ambos capaces de
  producir `UsuariosClientError::Unreachable` por el mismo camino.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (54 unitarios + todos los
  tests de integración sin Docker en verde, incluidos los 2 nuevos de
  `tests/openapi_docs.rs`; ninguna feature 1-9 se rompió), `cargo test --
  --ignored` (Docker disponible: los 3 tests existentes con RabbitMQ real
  siguen en verde), `cargo doc --no-deps` (sin warnings, tras corregir un
  `rustdoc::private_intra_doc_links` en el doc-comment de módulo) y
  `./init.sh` — todo en verde, 0 warnings. Detalle completo en
  `progress/impl_openapi_docs.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el test
  Docker), validar los 4 criterios de aceptación uno por uno contra el
  código/tests (líneas concretas citadas, incluyendo que cada código de
  status documentado coincide con el `StatusCode` real devuelto por cada
  handler), replicar el experimento del mecanismo anti-drift, y confirmar
  que la especificación generada no filtra ningún secreto (solo el nombre
  de la cookie de sesión en el `securityScheme`, nunca su valor/firma).
  Único hallazgo no bloqueante: faltaba el código `504` en `POST
  /api/scans`/`POST /api/scans/{scan_id}/cancel` (presente en sus
  endpoints hermanos) — corregido por el implementer antes de cerrar la
  sesión, con `cargo build`/`clippy`/`fmt --check`/`test` reconfirmados en
  verde tras el ajuste. Detalle completo en
  `progress/review_openapi_docs.md`.
- **Estado final:** feature 10 (`openapi_docs`) pasó a `"done"` en
  `feature_list.json`.

---

## 2026-09-19 — Feature 11: containerization — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  patrón directamente reutilizable ya validado en `user-service/Dockerfile`,
  repo hermano de solo lectura).
- **Investigación previa:** el leader revisó `user-service/Dockerfile`,
  `.dockerignore`, `docs/architecture.md`§Despliegue y
  `README.md`§"Despliegue (Docker)" como plantilla a adaptar (no copiar
  literal), y confirmó de antemano en `progress/current.md` las variables
  de entorno reales de `src/config.rs` y que el binario del paquete
  `gateway` (sin `[[bin]]` en `Cargo.toml`) ya se llama `gateway` por
  defecto.
- **Qué se hizo:** imagen Docker de producción de `gateway` (RF-09,
  ninguna lógica de negocio nueva en `src/`/`tests/`). Nuevo `Dockerfile`
  multi-stage en la raíz: stage `builder`
  (`rust:1.98-bookworm@sha256:82150a52...`, mismo digest que
  `user-service`, cachea la compilación de dependencias con un `src`
  placeholder antes de copiar el código real y compilar
  `cargo build --release`) y stage runtime
  (`gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79...`, mismo
  digest que `user-service`) con únicamente el binario `gateway` copiado
  y `USER nonroot`; sin stage de migraciones/sqlx (diferencia deliberada
  frente a `user-service`, que sí las embebe). El comentario del
  `Dockerfile` y la nota nueva de `docs/architecture.md` explicitan que
  los certificados CA de la base distroless cubren el TLS saliente hacia
  **3** destinos: Google (OIDC), `ms-usuarios` y el Broker (AMQPS), no
  solo uno. Nuevo `.dockerignore` que excluye `target/`, `.git/`,
  `.gitignore`, `.claude/`, `progress/`, `docs/`, `tests/`, `rabbitmq/`
  (fixtures de topología de `testcontainers`, confirmado por `grep` que
  solo las usa `cargo test`, nunca el binario de producción), `*.md`,
  `Dockerfile`, `.dockerignore`. `docs/architecture.md`§Despliegue
  **extendida** (no reemplazada): la nota ya existente sobre terminación
  TLS pública fuera del binario sigue intacta, con un párrafo nuevo sobre
  la imagen. `README.md`§"Despliegue (Docker)" relleno completo del
  placeholder: instrucciones de build, tabla de las 14 constantes `ENV_*`
  reales leídas de `src/config.rs` (13 requeridas + `GOOGLE_OIDC_ISSUER_URL`
  como única con valor por defecto), y un `docker run` de ejemplo con
  valores sintéticos de laboratorio (nunca credenciales reales).
- **Verificación:** `docker build -t gateway:local .` sin error (~101s,
  imagen final 51.7MB disco/13.4MB contenido); `docker inspect` confirma
  `USER` = `nonroot`; `docker run --rm --entrypoint sh ... -c "echo hi"`
  confirma ausencia de shell/toolchain en la imagen final; `docker run`
  con las 13 env vars requeridas (valores sintéticos) arranca el proceso,
  carga la configuración correctamente y falla limpiamente al no
  encontrar Google/Broker/ms-usuarios reales en este entorno —log `ERROR`
  estructurado, exit code 1, **sin panic ni credenciales en el log**.
  Limpieza: contenedores lanzados con `--rm`, imagen `gateway:local`
  eliminada explícitamente al terminar. `./init.sh` en verde (esta feature
  no toca `src/`/`tests/`). Detalle completo en
  `progress/impl_containerization.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras verificación
  independiente: repitió `docker build --no-cache -t gateway:review-check .`
  desde cero (sin depender de la caché del implementer, ~1m46s, éxito),
  confirmó ausencia de shell y usuario `nonroot` por su cuenta, repitió
  `docker run` con env vars sintéticas y confirmó el mismo comportamiento
  sin panic ni fuga de credenciales (además probó el caso sin ninguna env
  var: tampoco panickea), confirmó por `git diff docs/architecture.md` que
  la nota TLS pública original sigue intacta y solo se añadió texto nuevo,
  confirmó por `grep`/lectura directa de `src/config.rs` el conteo exacto
  de 14 `ENV_*` (13 requeridas + 1 con default) contra la tabla de
  `README.md`, y confirmó que `.dockerignore` no rompe el build real.
  Ejecutó `./init.sh` dos veces de forma independiente (regresión de las
  features 1-10, incluidos los 3 tests Docker vía testcontainers contra
  RabbitMQ real) sin encontrar regresiones. Recorrió los 5 checkpoints de
  `CHECKPOINTS.md` uno por uno, todos `[x]`. Sin cambios requeridos.
  Detalle completo en `progress/review_containerization.md`.
- **Estado final:** feature 11 (`containerization`) pasó a `"done"` en
  `feature_list.json`. Era la última feature pendiente del backlog de
  `feature_list.json`.

## 2026-09-24 — Feature 12: post_login_redirect — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Detectado en uso real (no en el backlog original):** desplegando en AWS,
  el login OIDC contra Google terminaba con éxito (código intercambiado,
  cookie de sesión emitida, verificado en devtools) pero `GET
  /auth/callback` respondía `200` vacío y el navegador quedaba en blanco,
  porque `front/src/auth/LoginButton.tsx` inicia el login con
  `window.location.href` (navegación de página completa, no XHR) y nunca
  vuelve a la SPA sin un redirect explícito de vuelta.
- **Qué se hizo:** nueva variable de entorno `FRONT_BASE_URL` en
  `src/config.rs` (`ENV_FRONT_BASE_URL`, requerida, `String` — mismo patrón
  `required_string`/`ConfigError::Missing` que el resto, sin valor
  hardcodeado). `AppState::front_base_url` (`src/api.rs`) recibe ese valor
  vía `src/wiring.rs`. El handler `callback` ahora devuelve `(CookieJar,
  Response)`: tras emitir la cookie de sesión, responde `302 Found` con
  `Location` fijado exactamente a `state.front_base_url` (reutilizando el
  helper `redirect_found` ya existente) — nunca concatenando ni reflejando
  ningún parámetro de la query string de la request original (mitigación de
  open redirect). Los caminos de error ya existentes (`400` por
  `state`/`code` ausente o no coincidente, `401` por ID token
  inválido/expirado/audiencia o nonce incorrectos, `500` por fallo de
  discovery/emisión de sesión) no se tocaron. La anotación
  `#[utoipa::path(...)]` de `GET /auth/callback` se actualizó (`200` →
  `302` en el camino feliz, con descripción explícita de la mitigación de
  open redirect). `README.md` documenta la nueva env var en la tabla y el
  ejemplo de `docker run`. `tests/oidc_login.rs`:
  `callback_with_valid_id_token_creates_session` ahora espera `302` +
  `Location == la URL de front configurada`; nuevo test
  `callback_success_redirect_ignores_extra_query_params` que agrega
  `redirect_uri`/`next` maliciosos a la query del callback y confirma que el
  `Location` no varía. Los demás `tests/*.rs` que construyen `AppState` a
  mano (`rate_limiting`, `scan_submission`, `scan_history_and_cancellation`,
  `scan_outcome_relay`, `session_middleware_and_me`,
  `usuarios_profile_proxy`) se actualizaron solo para agregar el nuevo
  campo `front_base_url` de laboratorio y seguir compilando, sin tocar sus
  aserciones.
- **Verificación:** `./init.sh` en verde — `cargo fmt --check`, `cargo
  clippy --all-targets -- -D warnings` sin advertencias, `cargo test` (9/9
  en `tests/oidc_login.rs`, resto de la suite sin regresiones), `cargo test
  -- --ignored` (3 tests contra RabbitMQ real vía `testcontainers`, Docker
  disponible en este entorno) y `cargo doc --no-deps` sin errores.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras verificación
  independiente: ejecutó `./init.sh` por su cuenta (mismo resultado en
  verde), confirmó línea por línea que `redirect_found` solo escribe
  `state.front_base_url` en `Location` sin interpolar `CallbackParams`
  (que solo modela `code`/`state`, así que cualquier query param adicional
  se ignora), confirmó que el mapeo de `AuthError` a status HTTP no fue
  tocado por esta feature, confirmó ausencia de fuga de credenciales/tokens,
  y recorrió los 5 checkpoints de `CHECKPOINTS.md` uno por uno, todos `[x]`.
  Sin cambios requeridos. Detalle completo en
  `progress/review_post_login_redirect.md`.
- **Estado final:** feature 12 (`post_login_redirect`) pasó a `"done"` en
  `feature_list.json`.

## 2026-09-24 — Feature 13: cors_for_front — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Detectado en uso real (no en el backlog original):** en el mismo
  despliegue en AWS de la feature 12, el login contra Google completaba
  bien (cookie `gateway_session` emitida, verificado con devtools), pero el
  usuario quedaba en un bucle infinito de redirect a `/auth/login`. Causa
  raíz: `front` y `gateway` corren en orígenes distintos del navegador
  (mismo host, puertos 80/8080), `front/src/auth/SessionProvider.tsx` llama
  `getMe()` al montar cualquier ruta protegida vía
  `front/src/api/httpClient.ts` (`fetch(..., { credentials: "include" })`,
  cross-origin real), y el gateway no tenía ninguna cabecera CORS — el
  navegador bloqueaba la respuesta de `/api/me` aunque el gateway la
  procesara bien, `performRequest` lo capturaba como `{networkError: true}`,
  y `SessionProvider` lo trataba como `ANONYMOUS_SESSION` -> `ProtectedRoute`
  volvía a `/auth/login`.
- **Qué se hizo:** `tower-http` (versión `0.6`, feature `cors`, reutiliza la
  resolución transitiva que ya fijaba `reqwest` en `Cargo.lock`) agregada a
  `Cargo.toml`. `src/config.rs`: nuevo campo `Config::front_origin: String`
  y helper `front_origin_from_base_url` (`url::Url::parse(...).origin()
  .ascii_serialization()`), invocado justo después de leer `FRONT_BASE_URL`
  en `Config::from_env` — deriva el *origen* (`scheme://host[:puerto]`, sin
  `path`) de la misma variable que ya existía desde la feature 12, en vez de
  reflejar el string crudo (que puede llevar `path`, p. ej.
  `https://front.example/post-login`, y el header `Origin` de un navegador
  nunca lo lleva). Nueva variante `ConfigError::InvalidUrl` si
  `FRONT_BASE_URL` no es una URL absoluta válida. `src/wiring.rs` convierte
  ese origen ya validado a `axum::http::HeaderValue`
  (`WiringError::InvalidCorsOrigin` si fallara, nunca debería) y lo guarda
  en el nuevo campo `AppState::front_origin`. `src/api.rs`: nueva función
  privada `cors_layer` que construye una `CorsLayer` con
  `allow_credentials(true)`, `allow_methods([GET, POST])`,
  `allow_headers([CONTENT_TYPE])`, y **`AllowOrigin::predicate`** (no
  `allow_origin(HeaderValue)`/`AllowOrigin::exact`) comparando a mano contra
  `front_origin` — se detectó con el primer test en rojo que `exact` fija un
  único valor de `Access-Control-Allow-Origin` en toda respuesta sin mirar
  el `Origin` real de la request, así que un origen no permitido también lo
  recibiría. `app_router` aplica esta `CorsLayer` como capa **externa**,
  tras fusionar todos los routers (incluido `protected_router`, que ya
  lleva `require_session` como su propia capa interna): así un preflight
  `OPTIONS` lo resuelve `tower_http::cors::Cors` por completo antes de
  llegar al middleware de sesión, sin exigirle cookie. Los 7 archivos de
  test que construyen `AppState` a mano (`tests/usuarios_profile_proxy.rs`,
  `rate_limiting.rs`, `session_middleware_and_me.rs`, `scan_submission.rs`,
  `scan_history_and_cancellation.rs`, `scan_outcome_relay.rs`,
  `oidc_login.rs`) se actualizaron solo para agregar el nuevo campo
  `front_origin` y seguir compilando, sin tocar sus aserciones. Nuevo
  `tests/cors.rs` (mismo patrón que `tests/session_middleware_and_me.rs`,
  sin Docker, con un `FRONT_BASE_URL` de prueba con `path` a propósito para
  demostrar que el origen derivado lo excluye): origen permitido recibe
  `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`;
  preflight `OPTIONS` a `/api/me` responde 200/204 sin cookie y con las
  cabeceras CORS correctas; origen no permitido no recibe
  `Access-Control-Allow-Origin` (la request se sigue procesando
  normalmente del lado del servidor); una request real con origen permitido
  pero sin sesión sigue devolviendo 401 (CORS no reemplaza la
  autorización). `src/config.rs` gana además
  `front_base_url_that_is_not_an_absolute_url_produces_typed_error` y un
  assert de `front_origin` en el test de config válida existente.
- **Verificación:** `./init.sh` en verde — `cargo fmt --check`, `cargo
  clippy --all-targets -- -D warnings` sin advertencias, `cargo test`
  (incluye los 4 nuevos de `tests/cors.rs` y los 2 nuevos de `config.rs`),
  `cargo test -- --ignored` (3 tests contra RabbitMQ real vía
  `testcontainers`, Docker disponible en este entorno), y `cargo doc
  --no-deps` sin errores ni warnings (se corrigió un intra-doc-link a un
  ítem privado introducido en el doc comment de `app_router`). Limpieza
  menor tras la revisión: `url = "2"` había quedado declarada tanto en
  `[dependencies]` (nueva) como en `[dev-dependencies]` (ya existía) —
  redundante e inocua, se quitó la duplicada en `[dev-dependencies]`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras verificación
  independiente: ejecutó `./init.sh` por su cuenta (mismo resultado en
  verde), confirmó que la derivación de `front_origin` desde
  `FRONT_BASE_URL` es una normalización correcta del mismo valor de
  configuración (RFC 6454) y no una desviación del `acceptance`, confirmó
  que `AllowOrigin::predicate` evita reflejar `Access-Control-Allow-Origin`
  a un origen no permitido (a diferencia de `AllowOrigin::exact`), confirmó
  que el preflight `OPTIONS` no pasa por `require_session` y que una
  request real sigue exigiendo sesión sin importar el `Origin`, confirmó
  ausencia de fuga de secretos, y recorrió los 5 checkpoints de
  `CHECKPOINTS.md` uno por uno, todos `[x]` (adaptando los ítems de C5 que
  asumen git, ya que en este entorno el repo no se reportó como
  repositorio git). Sin cambios requeridos. Detalle completo en
  `progress/review_cors_for_front.md`.
- **Estado final:** feature 13 (`cors_for_front`) pasó a `"done"` en
  `feature_list.json`. Era la última feature listada en
  `feature_list.json` a la fecha de este cierre.

## 2026-09-24 — Feature 14: network_credentials_proxy — DONE

- **Contexto:** `user-service` ya expone `POST`/`GET
  /users/me/network-credentials` y `DELETE
  /users/me/network-credentials/{id}` (feature `network_credentials_api`,
  ya `done` en ese repo hermano), pero `gateway` no tenía ningún proxy hacia
  esos 3 endpoints — solo existía el de perfil (`/api/profile`, feature
  `usuarios_profile_proxy`). Sin esto, un usuario no tenía forma de
  registrar credenciales de red y `POST /api/scans` siempre respondía `422`.
  Contrato confirmado por lectura directa de `../user-service/src/api.rs`
  (líneas ~401-483) y `../user-service/src/domain.rs::NetworkCredential`
  (líneas ~151-170), ambos de solo lectura (otro repo).
- **Implementación:** `src/usuarios_client.rs` gana el tipo
  `NetworkCredential` (`{id, user_id, target_pattern, network_user,
  has_sudo, created_at, updated_at}`, `created_at`/`updated_at` como
  `String` RFC 3339 igual que `ScanHistoryEntry`, deliberadamente sin
  `ssh_credentials_ref`, con `Serialize`+`Deserialize`+`ToSchema` porque este
  mismo tipo es tanto lo que se decodifica de `ms-usuarios` como lo que
  `crate::api` devuelve tal cual a `front`) y
  `CreateNetworkCredentialRequest` (con `ssh_credentials_ref`, `Debug`
  redactado a mano, mismo criterio que `ScanTargetCredentials`). Tres
  métodos nuevos en `UsuariosClient`: `list_network_credentials`/
  `create_network_credential` (mismo patrón exacto que
  `get_profile`/`upsert_profile`, vía `send_and_decode`) y
  `delete_network_credential` (mismo patrón que `update_scan_status` — sin
  `send_and_decode`, sin cuerpo que decodificar —, pero con una excepción
  deliberada: un `404` de `ms-usuarios` se distingue con una nueva variante
  `UsuariosClientError::NetworkCredentialNotFound` en vez de caer en
  `UnexpectedResponse` como el resto del cliente, porque el criterio de
  aceptación exige reenviar ese `404` tal cual — nunca el `502` genérico que
  usa `UnexpectedResponse`). `src/api.rs`: 3 rutas nuevas en
  `protected_router` (`GET`/`POST /api/network-credentials`, `DELETE
  /api/network-credentials/:id`), agregadas a `ROUTES` con
  `protected: true`, con su `#[utoipa::path(...)]` y registro en `ApiDoc`
  (nuevo tag `network-credentials`), y un nuevo arm en
  `impl IntoResponse for UsuariosClientError` mapeando
  `NetworkCredentialNotFound -> 404`. `docs/security-scope.md` gana la
  subsección "Credenciales de red (feature `network_credentials_proxy`)",
  reafirmando que `ssh_credentials_ref` nunca transita por una respuesta de
  este Gateway.
- **Tests:** `tests/network_credentials_proxy.rs` nuevo (mismo patrón que
  `tests/usuarios_profile_proxy.rs`, router completo vía `axum::serve` sobre
  un puerto efímero, stub HTTP real de `ms-usuarios`): camino feliz de los 3
  endpoints (incluida una verificación explícita de que la respuesta nunca
  incluye `ssh_credentials_ref` aunque el stub la incluya a propósito para
  probar la garantía a nivel de tipo), sesión ausente rechazada antes de
  tocar `ms-usuarios`, credencial de servicio rechazada -> `502` genérico
  (mismo criterio que el resto del repo para `UnexpectedResponse`),
  `ms-usuarios` caído -> `502`/`504` sin exponer su URL interna, y `DELETE`
  de una entrada ajena/inexistente -> `404`. Más 6 tests unitarios nuevos en
  `src/usuarios_client.rs` (URLs sin doble slash, redacción de `Debug` en
  `CreateNetworkCredentialRequest`, serialización de `NetworkCredential` sin
  `ssh_credentials_ref`, deserialización que ignora ese campo si llegara).
- **Verificación:** `cargo build --all-targets`, `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings` y `./init.sh` completo (con
  Docker disponible, incluyendo los tests `#[ignore]` contra RabbitMQ real)
  en verde. Se corrigió un warning de rustdoc
  (`broken_intra_doc_links`: `Self::` no resuelve en un doc-comment de
  módulo `//!`, se cambió a `UsuariosClient::resolve_scan_target`).
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras verificación
  independiente: releyó `docs/architecture.md`/`conventions.md`/
  `security-scope.md`/`CHECKPOINTS.md` y el `acceptance` completo de la
  feature 14, confirmó el contrato real contra `../user-service` línea por
  línea, confirmó que `NetworkCredential` nunca tiene `ssh_credentials_ref`,
  confirmó que el `404` de `delete_network_credential` se reenvía tal cual
  (excepción deliberada y documentada al patrón `UnexpectedResponse -> 502`
  del resto del cliente), confirmó que las 3 rutas están en `ROUTES`
  (`protected: true`) y documentadas en `ApiDoc` (cubierto por el test
  anti-drift de `tests/openapi_docs.rs`), corrió `./init.sh`/`clippy`/`fmt`
  por su cuenta con el mismo resultado en verde, y confirmó que no se tocó
  nada fuera de `gateway/`. Detalle completo en
  `progress/review_network_credentials_proxy.md`.
- **Estado final:** feature 14 (`network_credentials_proxy`) pasó a
  `"done"` en `feature_list.json`. Era la última feature listada en
  `feature_list.json` a la fecha de este cierre.

---

## 2026-09-24 — Feature 15: fix_logout_cookie_removal — DONE

- **Agente:** implementer (rol asumido directamente en esta sesión, sin
  subagente `implementer` disponible en el entorno) + subagente `reviewer`.
- **Bug (confirmado en producción, AWS, con devtools reales):** tras `POST
  /auth/logout`, la respuesta traía `Set-Cookie: gateway_session=; Path=/;
  Max-Age=0; Expires=<pasado>`, pero el navegador nunca borraba la cookie
  original — seguía existiendo con el JWT completo tras la recarga, y el
  usuario nunca quedaba deslogueado. Causa raíz: `session_cookie()`
  (`src/auth.rs`) construye la cookie original con `.http_only(true)
  .secure(true).same_site(SameSite::Strict)`, pero `removal_cookie()` solo
  fijaba `.path("/")` — sin `Secure`. Los navegadores modernos (política
  "Leave Secure Cookies Alone") rechazan que un `Set-Cookie` sin `Secure`
  sobreescriba/borre una cookie existente con `Secure` para el mismo
  nombre+path, así que el borrado se ignoraba en silencio.
- **Qué se hizo:** `removal_cookie()` (`src/auth.rs`, ~L432) ahora agrega
  `.http_only(true).secure(true).same_site(SameSite::Strict)` además del
  `.path("/")` que ya tenía — mismos atributos que `session_cookie()` salvo
  valor/expiración. No se tocó `CookieJar::remove()` (handler `logout` en
  `src/api.rs`), que ya fijaba correctamente `Max-Age=0`/`Expires` en el
  pasado.
- **Tests:** se extendió el test existente
  `removal_cookie_matches_session_cookie_name_and_path` (`src/auth.rs`)
  para comparar también `.secure()`, `.http_only()` y `.same_site()` de
  `removal_cookie()` contra los de una `session_cookie()` real construida
  en el propio test, además de nombre y path, cubriendo la regresión de
  este mismo bug.
- **Verificación:** `./init.sh` completo (unitarios, integración con
  Docker/testcontainers, `cargo doc --no-deps`), `cargo fmt --check` y
  `cargo clippy --all-targets -- -D warnings` — todos en verde, corridos
  tanto por el implementer como de forma independiente por el reviewer.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras releer
  `docs/architecture.md`/`conventions.md`/`security-scope.md`/
  `CHECKPOINTS.md`, confirmar que el diff se limita a `removal_cookie()` y
  su test en `src/auth.rs`, que ninguna ruta protegida quedó sin
  middleware, que no hay fuga de credenciales, y correr `./init.sh` por su
  cuenta con el mismo resultado en verde. Detalle completo en
  `progress/review_15.md`.
- **Estado final:** feature 15 (`fix_logout_cookie_removal`) pasó a
  `"done"` en `feature_list.json`. Era la última feature listada en
  `feature_list.json` a la fecha de este cierre.

---

## 2026-09-29 — Feature 16: robust_logout — DONE

- **Agente:** subagente `implementer` + subagente `reviewer` (coordinados
  por `leader`).
- **Bug (persistía en AWS, ECS Fargate detrás de ALB):** `POST
  /auth/logout` respondía `204` pero la sesión seguía activa. La feature 15
  (añadir `Secure` a `removal_cookie()`) no era la causa real: "Leave
  Secure Cookies Alone" solo aplica a respuestas servidas por HTTP, no
  HTTPS.
- **Causas raíz reales:** (1) el handler `logout` usaba
  `CookieJar::remove`, que solo emite el `Set-Cookie` de borrado si la
  request trae la cookie; detrás de un proxy puede no llegar y la respuesta
  era un `204` sin ningún `Set-Cookie`. (2) Ninguna respuesta del Gateway
  llevaba `Cache-Control`, así que un CDN/proxy podía servir un `GET
  /api/me` `200` cacheado después del logout.
- **Qué se hizo:**
  - `removal_cookie()` (`src/auth.rs`, ~L436-451) devuelve una cookie ya
    expirada por sí misma: `.max_age(CookieDuration::ZERO)` +
    `.expires(OffsetDateTime::UNIX_EPOCH)` (de `cookie::time`, sin
    dependencias nuevas), manteniendo `HttpOnly`/`Secure`/
    `SameSite=Strict`/`Path=/`. Rustdoc actualizado.
  - Handler `logout` (`src/api.rs`, ~L1359-1381) usa
    `jar.add(auth::removal_cookie())` (el `Set-Cookie` de borrado se emite
    siempre) y añade `Clear-Site-Data: "cookies"` (constante
    `CLEAR_SITE_DATA`, ~L1357). OpenAPI de `/auth/logout` sigue en `204`,
    solo se amplió la descripción.
  - `app_router` (`src/api.rs`, ~L1113-1122) añade
    `middleware::map_response(default_no_store)` como capa **más externa**
    (por fuera de la `CorsLayer` y de `require_session`): inserta
    `Cache-Control: no-store` solo si la respuesta no trae ya uno
    (`entry(..).or_insert(..)`), así que no pisa el `no-cache` del SSE.
    Cubre rutas públicas y protegidas, los `401` del middleware de sesión
    y las respuestas que genera la propia `CorsLayer` (preflight).
- **Tests:** unitario nuevo `removal_cookie_is_already_expired`
  (`src/auth.rs`); se conserva
  `removal_cookie_matches_session_cookie_name_and_path`. Integración nueva
  `logout_without_session_cookie_still_emits_an_expired_set_cookie`
  (`tests/oidc_login.rs`: POST sin cookie → `Set-Cookie` con `max-age=0`,
  `expires`, `path=/`, `secure`, `httponly`, `samesite=strict` y
  `Clear-Site-Data`). En `tests/session_middleware_and_me.rs` (sobre
  `app_router`): `me_with_valid_session_is_marked_no_store`,
  `me_without_session_is_rejected_and_marked_no_store`,
  `logout_is_marked_no_store`.
- **Verificación:** sin `cargo` local, `./init.sh` completo se corrió
  dentro de `rust:1.98-bookworm` (misma imagen que el `Dockerfile`), con el
  repo montado en `/run/desktop/mnt/host/c/Users/maldo/gateway` (para que
  los bind mounts de testcontainers resuelvan en Docker Desktop),
  `--network host`, socket de Docker montado y `/.dockerenv` borrado en el
  contenedor efímero (testcontainers 0.20.1 usa entonces `localhost`, que
  coincide con el SAN del cert de laboratorio generado con
  `rabbitmq/generate-lab-certs.sh`). Resultado: exit 0 — fmt, clippy
  `--all-targets -D warnings`, 61 unitarios + integración (115 en total,
  0 fallidos), 3 `--ignored` con testcontainers, `cargo doc` sin warnings.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras correr `./init.sh` de
  forma independiente con el mismo resultado y verificar los 9 criterios
  de acceptance y los checkpoints C1-C5. Observaciones no bloqueantes: no
  hay test de regresión del `no-cache` del SSE ni del `no-store` en
  preflight; `Clear-Site-Data: "cookies"` borra todas las cookies del
  origen del Gateway (hoy solo existe `gateway_session`). Detalle en
  `progress/review_robust_logout.md` (informe del implementer en
  `progress/impl_robust_logout.md`).
- **Estado final:** feature 16 (`robust_logout`) pasó a `"done"` en
  `feature_list.json`. Era la última feature listada en
  `feature_list.json` a la fecha de este cierre.

---

## 2026-10-01 — Feature 17: provision_user_profile_on_login — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  fix acotado a un solo handler, reutiliza `UsuariosClient::upsert_profile`
  y `UserProfile` ya existentes, sin crates ni APIs externas nuevas).
- **Contexto:** bug de integración confirmado en producción (AWS):
  `POST /api/network-credentials` respondía `502` para cualquier cuenta
  real. Causa raíz confirmada en `ms-usuarios`:
  `network_credentials.user_id REFERENCES users(user_id)`, y la única vía
  que crea esa fila es `PUT /users/me` — el callback OIDC de este Gateway
  nunca lo llamaba, así que ninguna cuenta que entra por Google llegaba a
  tener fila en `users`, y cualquier `INSERT` posterior con esa FK rompía
  con una violación de foreign key vista solo como `502`/`500` genérico del
  lado del cliente. Decisión de diseño (acordada con el usuario): el fix va
  en este Gateway, en el momento del login, no como upsert defensivo
  repetido en cada endpoint de `ms-usuarios`.
- **Qué se hizo:** en `fn callback` (`src/api.rs`), inmediatamente después
  de construir `Session` y antes de `auth::issue_session_token`/emitir la
  cookie/redirigir, se agregó una llamada a
  `state.usuarios_client.upsert_profile(&session, &serde_json::json!({ "display_name": session.name }))`
  — `display_name` sale siempre de `session.name` (ya verificado del ID
  token de Google), nunca de un parámetro de la request de callback. Nuevo
  enum `CallbackError` (`thiserror`, `#[error(transparent)]` sobre
  `AuthError`/`UsuariosClientError`, mismo patrón que `ScanSubmitError`),
  con `fn callback` devolviendo `Result<(CookieJar, Response), CallbackError>`
  en vez de `Result<_, AuthError>`; un fallo de `upsert_profile` se propaga
  con `?` sin llegar a issuar cookie ni `302`, delegando en el `IntoResponse`
  ya existente de cada error (sin inventar un mapeo HTTP nuevo). El
  `#[utoipa::path(...)]` de `/auth/callback` se amplió con las respuestas
  `502`/`504` (el `302` del camino feliz no cambia). No se tocó
  `usuarios_client.rs`: se reutilizan `UsuariosClient::upsert_profile` y
  `UserProfile` (`serde_json::Value`) tal cual los usaba ya el proxy
  `GET`/`PUT /api/profile`. En `tests/oidc_login.rs`, `spawn_gateway` ganó
  un parámetro `usuarios_base_url` (antes apuntaba siempre a una URL
  inválida nunca contactada, lo que habría roto el camino feliz tras el
  fix); se agregó un stub real de `ms-usuarios` (`PUT /users/me` sobre un
  puerto efímero, con modo `fail` para simular `5xx`) y 2 tests nuevos:
  éxito dispara `PUT /users/me` con el header de identidad y
  `display_name` correctos antes del `302`/`Set-Cookie`; un `5xx` de
  `ms-usuarios` no emite cookie ni `302` y responde `502` sin exponer la
  URL interna del stub en el cuerpo. `docs/security-scope.md` ganó una
  viñeta nueva en "Identidad y sesión" documentando esta llamada y
  reafirmando el origen verificado de `display_name`.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (todos los tests de las
  features 1-16 siguen en verde, incluidos los 12 de `tests/oidc_login.rs`
  con los 2 nuevos y los 2 de `tests/openapi_docs.rs` sin tocar), `cargo
  test -- --ignored` (Docker disponible: los 3 tests con RabbitMQ real
  —`scan_submission`, `scan_outcome_relay`, `scan_history_and_cancellation`—
  siguen en verde), `cargo doc --no-deps` y `./init.sh` — todo en verde, 0
  warnings. Detalle completo en
  `progress/impl_provision_user_profile_on_login.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el bloque
  `--ignored` con Docker), validar los 9 criterios de aceptación uno por
  uno contra el código y los tests (líneas concretas citadas), confirmar
  que `tests/openapi_docs.rs` (anti-drift) sigue pasando sin cambios
  manuales a pesar de que el shape de `#[utoipa::path]` de `/auth/callback`
  cambió, confirmar por `git diff --stat` que el alcance se limitó a
  `docs/security-scope.md`, `src/api.rs` y `tests/oidc_login.rs` (sin tocar
  `usuarios_client.rs` ni ningún repo hermano), y confirmar que ningún log
  o cuerpo de error filtra el token de Google, la sesión firmada, la
  credencial de `ms-usuarios` o la credencial AMQPS. Sin cambios
  requeridos. Detalle completo en
  `progress/review_provision_user_profile_on_login.md`.
- **Estado final:** feature 17 (`provision_user_profile_on_login`) pasó a
  `"done"` en `feature_list.json`. No quedan features `pending` ni
  `in_progress` en `feature_list.json` a la fecha de este cierre.

---

## 2026-10-01 — Feature 18: broker_publisher_reconnect — DONE

- **Agente:** leader (orquestando implementer + reviewer, sin explorers:
  refactor de concurrencia acotado a un struct de `src/broker.rs`, sin
  crates nuevas — `tokio::sync::RwLock` ya es dependencia transitiva de
  `tokio`).
- **Investigación previa:** el leader confirmó la estructura real de
  `BrokerPublisher` (`connection`/`channel` como campos directos, sin
  interior-mutability ni datos guardados para reconectar) y que
  `publish_and_confirm` ya diferenciaba `PublishFailed`/`ConnectionFailed`
  de `NotAcknowledged` antes de despachar al implementer. Incidente real en
  AWS documentado en la propia feature: ECS reemplaza la task de RabbitMQ
  tras un health check fallido, la `Connection`/`Channel` de `gateway`
  queda apuntando a una instancia muerta, y todo `POST /api/scans` falla
  con `502` hasta reiniciar `gateway` a mano, aunque RabbitMQ ya esté sano.
- **Qué se hizo:** `src/broker.rs` — `BrokerPublisher` guarda su conexión y
  canal vigentes agrupados en un struct privado `PublisherConnection`
  detrás de `conn: RwLock<PublisherConnection>`, junto con `amqps_url:
  SecretString`, `vhost: String` y `ca_pem: Option<String>` (fuente para
  reconstruir `OwnedTLSConfig` al reconectar, ya que ese tipo de `lapin`/
  `tcp-stream` 0.28.0 no deriva `Clone`). `connect`/`connect_with_ca_pem`
  no cambiaron de firma pública. `publish_and_confirm` se dividió en un
  intento base (`try_publish_and_confirm`, solo toma un `read()` del lock —
  publicaciones sanas concurrentes no se serializan entre sí) y la lógica
  de reconexión: si el primer intento falla con un error de conexión
  (`is_connection_error`, nueva función privada que distingue
  `PublishFailed`/`ConnectionFailed` de `NotAcknowledged` — un nack real
  nunca dispara reconexión), se reconecta exactamente una vez
  (`reconnect()`, que escala a `write()` y hace *double-checked locking*:
  si otra tarea ya reconectó mientras esta esperaba el lock, no abre una
  segunda conexión real) y se reintenta la publicación una sola vez,
  propagando siempre el error **original** del primer intento si la
  reconexión o el reintento también fallan. `is_connected()` pasó de
  síncrona a `async fn` (ahora lee a través del lock); se verificó en todo
  el repo que ningún llamante de producción ni de tests la invocaba
  todavía, así que el cambio no rompe ningún contrato existente.
  `BrokerConsumer` no se tocó de forma observable (comparte
  `connect_channel`, sin cambios; sigue sin reconexión, documentado
  explícitamente en la nota de diseño del módulo, que ahora distingue el
  comportamiento del publicador del consumidor). Nuevo archivo
  `tests/broker_publisher_reconnect.rs` (`#[ignore = "requiere Docker"]`,
  mismo patrón `testcontainers` que `scan_submission.rs`/
  `scan_outcome_relay.rs`): fuerza el cierre de la conexión AMQP
  subyacente de un `BrokerPublisher` real vía la Management HTTP API de
  `rabbitmq:4.3.5-management` (`DELETE /api/connections/{name}`, con el
  usuario `lab-admin`, más simple y determinista que reiniciar el
  contenedor entero), espera con polling acotado a que `is_connected()`
  refleje el corte, y confirma que una publicación posterior tiene éxito
  —verificando el mensaje real en una cola de prueba, no solo el resultado
  del método— sin reiniciar el proceso ni reconstruir el publicador (misma
  instancia de principio a fin). 4 tests unitarios nuevos para
  `is_connection_error`.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (65 unitarios + toda la
  suite de integración sin Docker en verde, ninguna feature 1-17 se
  rompió), `cargo test -- --ignored` (Docker disponible: todos los
  `#[ignore]` en verde, incluido el nuevo de esta feature), `cargo doc
  --no-deps` (se corrigió un warning de `rustdoc::private_intra_doc_links`
  detectado en esta misma verificación) y `./init.sh` — todo en verde, 0
  warnings. Detalle completo en
  `progress/impl_broker_publisher_reconnect.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el bloque
  `--ignored` con Docker), validar los 7 criterios de aceptación uno por
  uno contra el código y los tests (líneas concretas citadas), confirmar
  con `rg "is_connected" .` en todo el repo que el cambio sync→async no
  rompe ningún llamante existente, confirmar por `git diff` que
  `src/wiring.rs` y el trait `ScanRequestPublisher` no cambiaron, y que las
  únicas líneas tocadas de `BrokerConsumer` son comentarios de la nota de
  diseño del módulo. Confirmó que la credencial AMQPS sigue sin loggearse
  (`amqps_url`/`ca_pem` nunca aparecen en un log, `BrokerPublisher`/
  `PublisherConnection` no derivan `Debug`) y que no hay `unwrap`/`expect`/
  `panic!` nuevos fuera de tests en `src/broker.rs`. Sin cambios
  requeridos. Detalle completo en
  `progress/review_broker_publisher_reconnect.md`.
- **Estado final:** feature 18 (`broker_publisher_reconnect`) pasó a
  `"done"` en `feature_list.json`.

---

## 2026-10-01 — Feature 19: log_broker_publish_errors — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Qué se hizo:** fix de observabilidad acotado. `BrokerError::PublishFailed`/
  `ConnectionFailed`/`ConsumeFailed` ya guardaban el `lapin::Error` original
  como `#[source]` (`thiserror`), a propósito nunca incluido en su `Display`
  (para no filtrar la URL/credencial AMQPS) — pero el único log existente de
  cada call site usaba `%err` (Display), así que ese `lapin::Error` real
  tampoco llegaba nunca al log del servidor. Se corrigieron los 3 call sites
  reales (identificados por el leader vía grep, no solo el nombrado en la
  descripción de la feature): `src/api.rs:904` (`ScanCancelError::Broker`),
  `src/api.rs:1524` (`ScanSubmitError::Broker`, el nombrado explícitamente) y
  `src/broker.rs:648-650` (`BrokerConsumer::run`, construye
  `BrokerError::ConsumeFailed` inline) — en los 3, `error = %err` pasó a
  `error = ?err` (Debug). `BrokerError` deriva `#[derive(Debug,
  thiserror::Error)]`, así que el `Debug` derivado encadena el `lapin::Error`
  real vía `#[source]` sin tocar el `impl Display` manual (`#[error("...")]`),
  que sigue siendo exactamente el mismo texto genérico expuesto a cualquier
  llamante HTTP. Se verificó además, leyendo el código fuente real de
  `lapin` 2.5.5 (`error.rs`), que ninguna variante de `lapin::Error`
  transporta la URL/credencial AMQPS, así que loguear su `Debug` es seguro.
  Los otros `tracing::error!/warn!` cercanos en `src/broker.rs` (líneas
  ~660-700) loguean un `lapin::Error`/`serde_json::Error` crudo directamente
  (no un `BrokerError` envuelto) y quedaron fuera de alcance a propósito, sin
  scope creep. `docs/security-scope.md` no requirió ningún cambio: ya
  documentaba que "el detalle real" va "solo en logs del lado del servidor
  (sin credenciales)". Se agregaron 2 tests unitarios nuevos en
  `src/broker.rs` (`publish_failed_display_never_changes_...`,
  `publish_failed_debug_includes_the_real_source_lapin_error`) y un test de
  integración end-to-end nuevo en `tests/scan_submission.rs`
  (`scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error`,
  con un doble `AlwaysFailsToPublish`) que confirma que `POST /api/scans`
  sigue respondiendo `502` con el mismo cuerpo exacto de antes, sin filtrar
  el detalle interno del `lapin::Error`.
- **Verificación:** `cargo build`, `cargo clippy --all-targets -- -D
  warnings`, `cargo fmt --check`, `cargo test` (todo verde, incluye el test
  nuevo; ninguna feature 1-18 se rompió) y `./init.sh` completo (Docker
  disponible: los `#[ignore]` también pasaron, incluido `cargo doc
  --no-deps` sin warnings) — todo en verde. Detalle completo en
  `progress/impl_log_broker_publish_errors.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) tras re-ejecutar de forma
  independiente todos los comandos de verificación (incluido el bloque
  `--ignored` con Docker), validar los 4 criterios de aceptación uno por uno
  contra el código/tests (líneas concretas citadas), confirmar por `git
  diff docs/security-scope.md` vacío que el documento sigue siendo preciso
  sin cambios, y confirmar que los demás `tracing::error!/warn!` de
  `src/broker.rs` no fueron tocados (sin scope creep). Sin cambios
  requeridos. Detalle completo en
  `progress/review_log_broker_publish_errors.md`.
- **Estado final:** feature 19 (`log_broker_publish_errors`) pasó a
  `"done"` en `feature_list.json`.

---

## 2026-10-01 — Feature 20: scan_outcome_consumer_reconnect — DONE

- **Agente:** leader (orquestando implementer + reviewer).
- **Investigación previa:** el leader confirmó, leyendo `src/broker.rs`
  completo y `src/wiring.rs`, que `BrokerConsumer::run(self, ...)` consume
  `self` por valor y corre en una única tarea (`tokio::spawn`, lanzada una
  sola vez al arrancar el proceso) — a diferencia de `BrokerPublisher`
  (feature 18, ya `done`), no hay llamadas concurrentes que proteger, así
  que no haría falta el `RwLock`/double-checked locking del publicador. Se
  confirmó por `grep` que `docs/architecture.md` no tenía todavía ninguna
  nota sobre reconexión del Broker (la descripción de la feature insinuaba
  "reemplazar" una nota existente que en realidad no existía).
- **Qué se hizo:** `BrokerConsumer` (relay de `gateway.scan-outcomes` hacia
  SSE, feature 7) reconecta en vez de terminar en silencio. `src/broker.rs`
  gana en `BrokerConsumer` los mismos 3 campos que ya tenía `BrokerPublisher`
  (`amqps_url: SecretString`, `vhost: String`, `ca_pem: Option<String>`,
  poblados en `connect_with_tls_config` con el mismo patrón) para poder
  reconectar sin pedírselos de nuevo al llamante. `BrokerConsumer::run` se
  reescribió: desestructura `self` en variables locales mutables y envuelve
  la lógica de consumo en un `loop`; al fallar `basic_consume` o agotarse el
  `Stream` de entregas (sin mecanismo de shutdown ordenado en este
  codebase, cualquier fin de stream se trata como fallo de conexión), llama
  al nuevo helper privado `reconnect_consumer` (reutiliza `connect_channel`,
  la función libre ya compartida con el publicador, sin duplicarla) con
  backoff exponencial simple — `RECONNECT_MAX_ATTEMPTS = 5`, esperas de
  1s/2s/4s/8s entre los 5 intentos (~15s acumulados en el peor caso; el 5.º
  intento, si también falla, ya no espera y se rinde de inmediato) — y si
  reconecta, reemplaza `connection`/`channel` y retoma el consumo; si se
  agotan los intentos, loguea el `lapin::Error` real (`?err`, Debug, mismo
  criterio que la feature 19) y termina, terminal como antes. `BrokerPublisher`
  no se tocó (solo comparte `connect_channel`). `docs/architecture.md` gana
  una nota breve nueva (no reemplaza ninguna existente) junto a la sección
  de notificación SSE, explicando que tanto publicador como consumidor
  reconectan solos y por qué el publicador necesita `RwLock` y el consumidor
  no. Nuevo archivo `tests/scan_outcome_consumer_reconnect.rs`
  (`#[ignore = "requiere Docker"]`, mismo patrón `testcontainers` que
  `scan_outcome_relay.rs`/`broker_publisher_reconnect.rs`): fuerza el cierre
  de la conexión AMQP del consumidor vía la Management HTTP API (reutiliza
  el mecanismo de `broker_publisher_reconnect.rs`), espera
  determinísticamente (polling de `/api/connections`, sin tiempos fijos ni
  republicación a ciegas) a que aparezca una conexión nueva, y confirma que
  un escaneo publicado después sigue relayándose por SSE sin reiniciar el
  proceso de gateway (misma tarea `tokio::spawn` de principio a fin del
  test), además de un sanity check previo a la caída (el relay sigue
  funcionando igual mientras la conexión está sana).
- **Corrección post-revisión (no bloqueante):** el reviewer notó que el
  doc-comment original describía el backoff como "1s/2s/4s/8s/16s" (~31s),
  pero el código real nunca llega a usar una 5.ª espera (el intento 5, si
  falla, se rinde sin esperar) — total real ~15s con 4 esperas. Se
  corrigieron los doc-comments de `src/broker.rs` (cabecera del módulo,
  `RECONNECT_INITIAL_BACKOFF`, `BrokerConsumer::run`, `reconnect_consumer`)
  y `progress/impl_scan_outcome_consumer_reconnect.md` para describir el
  comportamiento real (opción más simple que ajustar el código, sin impacto
  en `docs/architecture.md`, que no mencionaba el detalle numérico), y se
  re-ejecutaron `cargo fmt --check`/`cargo clippy --all-targets -- -D
  warnings`/`cargo doc --no-deps`/`cargo test`/`cargo test -- --ignored`,
  todos en verde.
- **Verificación:** `cargo build`, `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (67 unitarios + tests de
  integración sin Docker en verde, ninguna feature 1-19 se rompió), `cargo
  test -- --ignored` (Docker disponible: 5 tests de integración con
  RabbitMQ real, incluido el nuevo de esta feature en 15.4s, sin
  contenedores huérfanos), `cargo doc --no-deps` (sin warnings, tras
  corregir enlaces `rustdoc::private_intra_doc_links` a los nuevos símbolos
  privados) y `./init.sh` — todo en verde, 0 warnings. Detalle completo en
  `progress/impl_scan_outcome_consumer_reconnect.md`.
- **Revisión:** `reviewer` aprobó (`APPROVED`) verificando los 6 criterios
  de aceptación uno por uno, la decisión de no usar `RwLock` (correcta para
  una tarea única sin concurrencia) y confirmando que no hay fuga de
  credenciales. Única observación no bloqueante: discrepancia entre el
  doc-comment/informe y el comportamiento real del backoff (ver corrección
  arriba, ya resuelta). Detalle completo en
  `progress/review_scan_outcome_consumer_reconnect.md`.
- **Estado final:** feature 20 (`scan_outcome_consumer_reconnect`) pasó a
  `"done"` en `feature_list.json`.
