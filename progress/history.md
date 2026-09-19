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
