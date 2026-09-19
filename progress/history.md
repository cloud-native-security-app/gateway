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
