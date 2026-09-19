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
