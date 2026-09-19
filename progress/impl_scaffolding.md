# Implementación — feature 1: scaffolding

## Archivos creados

- `Cargo.toml` — crate `gateway`, edition 2021. Dependencias: `tokio`
  (`rt-multi-thread`, `macros`), `axum`, `lapin` (`features = ["rustls"]`,
  `default-features = false` para evitar el backend nativo-tls por defecto),
  `tracing`, `tracing-subscriber`, `serde` (`derive`), `serde_json`.
  Dev-dependency: `testcontainers`.
- `src/lib.rs` — doc-comment de crate, `#![deny(missing_docs)]`, declara
  `pub mod` para `api`, `auth`, `broker`, `config`, `domain`, `realtime`,
  `usuarios_client` (orden alfabético, como aplica `rustfmt`/convención de
  imports agrupados). Expone `pub async fn run()` documentada, que solo
  loguea `"starting"` vía `tracing::info!` — sin lógica de negocio de otras
  features.
- `src/main.rs` — envoltorio delgado: `#[tokio::main]`, inicializa
  `tracing_subscriber::fmt::init()` y llama a `gateway::run().await`. Sin
  `#![deny(missing_docs)]` (según convención, va solo en `lib.rs`).
- `src/config.rs`, `src/domain.rs`, `src/auth.rs`, `src/usuarios_client.rs`,
  `src/broker.rs`, `src/realtime.rs`, `src/api.rs` — cada uno con su
  doc-comment `//!` de módulo (propósito, según `docs/architecture.md`
  §Capas) y sin ítems públicos todavía (no dispara `missing_docs`; ningún
  módulo implementa lógica de negocio de las features 2-11, tal como pide
  el alcance de esta tarea).

No se creó módulo `wiring` (capa 8 de `docs/architecture.md`): la lista de
`acceptance` de la feature 1 en `feature_list.json` solo exige
`config, domain, auth, usuarios_client, broker, realtime, api`. Lo dejo
anotado aquí por si una feature futura lo necesita explícitamente — no lo
inventé por mi cuenta.

## Verificación de cada criterio de aceptación

1. **Cargo.toml con dependencias exactas** — verificado leyendo el archivo
   generado; `cargo build` resuelve y compila `tokio`, `axum`, `lapin`
   (con `rustls-connector`/`tokio-rustls` en el árbol de dependencias),
   `tracing`, `tracing-subscriber`, `serde`, `serde_json`. OK.
2. **`src/lib.rs` con los 7 módulos `pub`** — verificado por lectura directa
   del archivo y porque `cargo build`/`cargo doc` no fallan al resolver
   `crate::api`, `crate::auth`, etc. OK.
3. **`src/main.rs` envoltorio delgado** — inicializa runtime tokio (macro
   `#[tokio::main]`) y `tracing_subscriber`, delega el resto en
   `gateway::run()`. Ninguna otra lógica. OK.
4. **`#![deny(missing_docs)]` en la raíz del crate** — presente en la
   primera línea ejecutable de `src/lib.rs` (tras el doc-comment del
   crate). `cargo build`/`cargo doc` compilan sin error, confirmando que no
   hay ítems públicos sin documentar. OK.
5. **`testcontainers` como dev-dependency** — presente en
   `[dev-dependencies]` de `Cargo.toml`; se descarga y compila al correr
   `cargo test`. OK.
6. **`cargo build` sin warnings** — ejecutado dos veces (limpio y con caché
   de deps ya compiladas); `cargo build 2>&1 | grep -i warning` no
   encontró coincidencias (exit code 1 de `grep` = sin matches). OK.

## Comandos ejecutados y resultado

- `cargo build` → compila, 0 warnings.
- `cargo fmt --check` → sin diferencias.
- `cargo clippy --all-targets -- -D warnings` → sin advertencias.
- `cargo test` (sin `--ignored`) → 3 suites de tests (lib, main, doc-tests),
  0 tests en cada una (esperado: scaffolding puro, sin lógica que testear
  todavía; no hay tests de integración con Docker en esta feature).
- `cargo test -- --ignored` → igual, 0 tests, sin fallos.
- `cargo doc --no-deps` → genera `target/doc/gateway/index.html` sin
  errores.
- `./init.sh` → termina con **exit code 0**, todos los bloques `[OK]`.

## Dudas / bloqueos

Ninguno. La feature es puramente de scaffolding y no toca login/sesión,
la credencial compartida con `ms-usuarios`, ni credenciales del Broker, así
que no fue necesario consultar `docs/security-scope.md` para esta tarea (se
leyó igualmente `AGENTS.md`, `docs/architecture.md`, `docs/conventions.md`
y `CHECKPOINTS.md` como exige el protocolo).

No modifiqué `feature_list.json` (el estado de la feature 1 ya estaba en
`in_progress` al iniciar esta sesión; queda pendiente que el `leader` la
pase a `done` tras la revisión del `reviewer`).
