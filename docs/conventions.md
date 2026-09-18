# Convenciones de código

> Homogeneidad extrema. La IA predice mejor cuando el repositorio se parece
> a sí mismo en todas partes.

## Estilo Rust

- **Edition:** 2021 o superior.
- **Formato:** `cargo fmt` (configuración por defecto salvo que se documente
  lo contrario en `rustfmt.toml`).
- **Lints:** `cargo clippy --all-targets -- -D warnings` debe pasar sin
  advertencias (incluye el código de `tests/`, no solo `src/`).
- **Async:** runtime `tokio`. Ninguna llamada bloqueante directamente en una
  tarea async — usar `spawn_blocking` si la dependencia no es nativamente
  async.
- **Errores:** tipos de error propios por módulo con `thiserror` (variantes
  específicas, no `String`). `anyhow` solo se permite en `main.rs` o en el
  borde del proceso, nunca en la firma pública de una función de dominio.
- **Nada de `unwrap()`/`expect()`/`panic!()`** fuera de tests, a menos que la
  condición sea verdaderamente irrecuperable y esté documentada con un
  comentario explicando por qué.
- **Rustdoc:** todo ítem público (`pub fn`, `pub struct`, `pub enum`,
  `pub trait`) lleva un comentario `///` explicando su propósito (qué hace,
  qué puede fallar). El crate activa `#![deny(missing_docs)]` en
  `src/lib.rs` (no en `src/main.rs`).
- **Tests de integración con IO real:** se levantan con el crate
  `testcontainers` (contenedor `rabbitmq:management` oficial, mismo tag que
  usa `broker/docker-compose.yml`, para `broker`; un servidor HTTP de test
  en memoria o un stub real para `usuarios_client`). Nunca mocks del canal
  AMQP — ver `docs/verification.md`.
- **Todo test que dependa de Docker vía `testcontainers` se marca**
  `#[ignore = "requiere Docker"]`. Así `cargo test` (sin flags) corre rápido
  y sin depender de Docker, y `cargo test -- --ignored` corre específicamente
  los de integración. `init.sh` ejecuta ambos.

## Nombres

| Tipo                    | Convención        | Ejemplo                |
|-------------------------|-------------------|--------------------------|
| Módulos/archivos        | `snake_case`      | `usuarios_client.rs`, `broker.rs` |
| Tipos/traits            | `PascalCase`      | `ScanSubmission`, `BrokerError` |
| Funciones / variables   | `snake_case`      | `publish_scan_request`  |
| Constantes              | `UPPER_SNAKE`     | `DEFAULT_SESSION_TTL`   |
| Módulos privados        | prefijo `_` en el ítem, no en el módulo | `_internal_helper` |

## Estructura de un módulo

```rust
//! Una línea describiendo el propósito del módulo.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::ScanSubmission;

// tipos y lógica del módulo
```

- Imports: primero `std`, luego crates externos, luego `crate::...` — cada
  grupo separado por una línea en blanco (orden que aplica `rustfmt`
  automáticamente).

## Tests

- Tests unitarios: `#[cfg(test)] mod tests` al final del propio archivo,
  para lógica pura (`domain`, validación de IP/rango).
- Tests de integración: en `tests/`, un archivo por módulo que cruza un
  límite de IO real (`broker`, `usuarios_client`, `api` end-to-end).
- Los tests de `broker` corren contra un contenedor `rabbitmq:management`
  real con la topología copiada de `broker/rabbitmq/definitions.json` (ver
  `docs/architecture.md`), nunca contra el Broker de producción ni con un
  mock del protocolo AMQP.
- Los tests de `usuarios_client` corren contra un servidor HTTP de test que
  implementa el contrato documentado de `ms-usuarios` (nunca contra
  `user-service` de producción).
- Nombres de test descriptivos:
  `rejects_request_when_session_cookie_is_expired`.

## Manejo de errores (ejemplo)

```rust
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("no se pudo conectar al Broker")]
    ConnectionFailed,
    #[error("fallo al publicar en {exchange}")]
    PublishFailed { exchange: &'static str },
    #[error("error inesperado de backend")]
    Backend,
}
```

Los mensajes de error nunca incluyen el token de Google, la sesión firmada,
la credencial compartida con `ms-usuarios`, ni la credencial AMQPS.

## Comentarios

Por defecto **no** se escriben. Solo se permiten cuando explican un *por qué*
no obvio (p. ej. workaround documentado, invariante sutil, restricción de
`docs/security-scope.md`). Los nombres deben hacer el resto.
