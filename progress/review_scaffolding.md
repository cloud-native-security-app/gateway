# Review — feature 1 (scaffolding)

**Veredicto:** APPROVED

## Verificación de comandos (ejecutados por el reviewer, no solo leídos del informe)

- `cargo build` (tras `cargo clean -p gateway` para descartar caché) → `Finished
  dev profile [unoptimized + debuginfo] target(s) in 0.70s`, 0 warnings.
- `cargo clippy --all-targets -- -D warnings` → `Finished` sin advertencias.
- `cargo fmt --check` → sin diferencias (exit 0).
- `cargo test` → 3 suites (`unittests src/lib.rs`, `unittests src/main.rs`,
  `Doc-tests gateway`), cada una `0 passed; 0 failed; 0 ignored` — correcto
  para scaffolding puro, sin tests Docker colados.
- `cargo test -- --ignored` → mismo resultado, 0 tests, sin fallos.
- `cargo doc --no-deps` → genera `target/doc/gateway/index.html` sin error
  (confirma que `#![deny(missing_docs)]` no dispara: no hay ítems públicos
  sin documentar).
- `./init.sh` → exit code 0, todos los bloques `[OK]` (entorno, archivos
  base, `feature_list.json` válido, fmt/clippy/test/test --ignored/doc).
- `cargo tree -e normal | grep -iE "lapin|rustls|native-tls"` → confirma que
  `lapin v2.5.5` resuelve `rustls-connector`/`rustls` en el árbol de
  dependencias, sin `native-tls` presente (cumple
  `default-features = false` + `features = ["rustls"]`).

## Criterios de aceptación (feature 1, `feature_list.json`)

1. **Cargo.toml con dependencias exactas** — PASA. `Cargo.toml` declara
   `tokio { features = ["rt-multi-thread", "macros"] }`, `axum = "0.7"`,
   `lapin { version = "2", features = ["rustls"], default-features = false }`,
   `tracing = "0.1"`, `tracing-subscriber = "0.3"`,
   `serde { features = ["derive"] }`, `serde_json = "1"`, edition `"2021"`.
   Verificado por lectura directa y por `cargo tree` (ver arriba).

2. **`src/lib.rs` con los 7 módulos `pub`** — PASA. `src/lib.rs` líneas
   10-16 declaran `pub mod api; pub mod auth; pub mod broker; pub mod
   config; pub mod domain; pub mod realtime; pub mod usuarios_client;` en
   orden alfabético. Los 7 archivos correspondientes existen en `src/` y
   cada uno trae su doc-comment `//!` describiendo su capa según
   `docs/architecture.md` §Capas (config, domain, auth, usuarios_client,
   broker, realtime, api) — sin ítems públicos ni lógica de negocio de
   features 2-11, tal como exige el alcance de "solo scaffolding".

3. **`src/main.rs` envoltorio delgado** — PASA. `src/main.rs` (7 líneas):
   `#[tokio::main] async fn main()` que solo llama
   `tracing_subscriber::fmt::init()` y `gateway::run().await`. Ninguna
   lógica adicional.

4. **`#![deny(missing_docs)]` en la raíz del crate** — PASA. Presente en
   `src/lib.rs` línea 8, después del doc-comment de crate (líneas 1-6) y
   antes de las declaraciones `pub mod` (línea 10 en adelante) — cumple
   también `docs/conventions.md` ("en `src/lib.rs`, no en `src/main.rs`").
   `cargo doc --no-deps` compila sin error, confirmando que no hay ítems
   públicos sin `///`.

5. **`testcontainers` como dev-dependency** — PASA. `Cargo.toml`
   `[dev-dependencies]` → `testcontainers = "0.20"`.

6. **`cargo build` sin warnings** — PASA. Verificado con build limpio
   (`cargo clean -p gateway` + `cargo build`), sin salida de warnings.

## Conformidad adicional

- **`docs/conventions.md`**: imports no aplica (no hay `use` externos
  todavía); nombres de módulo en `snake_case` correctos
  (`usuarios_client.rs`, `broker.rs`, etc.); no hay `unwrap()`/`expect()`/
  `panic!()`/`println!()`/`dbg!()` en ningún archivo de `src/`; no hay
  comentarios explicativos superfluos (solo doc-comments `//!` de
  propósito, permitidos y exigidos).
- **`docs/architecture.md` §Capas**: los 7 módulos declarados corresponden
  exactamente a las capas 1-7 documentadas (`config`, `domain`, `auth`,
  `usuarios_client`, `broker`, `realtime`, `api`). El implementador dejó
  constancia explícita (en `progress/impl_scaffolding.md`) de no haber
  creado `wiring` (capa 8) porque no está en la lista `acceptance` de la
  feature 1 — decisión correcta: no se infiere alcance no pedido, evita
  módulos vacíos sin uso todavía. No hay lógica de negocio de otras
  features colada en ningún módulo (todos son solo doc-comment de módulo,
  sin tipos ni funciones).
- **Seguridad (`docs/security-scope.md`)**: no aplica en esta feature —
  no hay credenciales, sesión, ni tokens involucrados en scaffolding puro.
  Ningún log ni código toca el token de Google, la sesión firmada, la
  credencial de `ms-usuarios` ni la credencial AMQPS.
- **RF-10 (middleware de sesión en rutas protegidas)**: no aplica —
  todavía no existe ningún router ni ruta (`src/api.rs` solo tiene el
  doc-comment de módulo, sin handlers).

## Checkpoints (`CHECKPOINTS.md`) — relevantes a esta feature

- C1 (arnés completo): [x] — los 4 archivos base y los 4 docs existen;
  `./init.sh` exit code 0.
- C2 (estado coherente): [x] — una sola feature `in_progress` (id=1);
  `progress/current.md` refleja la sesión activa, sin basura de sesiones
  previas.
- C3 (arquitectura): [x] — `src/` solo contiene los módulos previstos
  (falta `wiring`, pero es capa 8, no exigida por la feature 1 y
  justificadamente pospuesta); toda dependencia de `Cargo.toml` está
  justificada por la propia feature 1; sin `println!`/`dbg!`/`unwrap`/
  `panic!` fuera de tests; `cargo doc --no-deps` sin warnings; no hay
  shape de API inventado (no aplica todavía, sin lógica).
- C4 (verificación real): parcial [ ] — `cargo test`/`clippy` verdes, pero
  todavía no hay ningún test de integración por módulo de IO (`auth`,
  `usuarios_client`, `broker`, `api`); es **esperado** en esta feature
  (scaffolding puro, sin lógica que testear), no es un defecto de esta
  feature sino un checkpoint que se completa en features posteriores.
- C5 (cierre de sesión): [x] — no hay archivos sueltos sospechosos,
  `.gitignore` cubre `/target` y `*.tmp`; queda pendiente que el leader
  anote la entrada en `progress/history.md` al cerrar, y marque la feature
  1 como `done` en `feature_list.json` (fuera del alcance del implementer/
  reviewer).

## Cambios requeridos

Ninguno. Los 6 criterios de aceptación de la feature 1 pasan con evidencia
verificada de forma independiente (no solo por el informe del
implementer), `./init.sh` termina en verde, y el código respeta
`docs/architecture.md` y `docs/conventions.md`.
