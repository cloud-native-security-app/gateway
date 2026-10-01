# Implementación — feature 19: log_broker_publish_errors

## Archivos modificados

- `src/api.rs`
  - Línea ~903-910 (`ScanCancelError::Broker` dentro de su `impl IntoResponse`):
    `tracing::error!(error = %err, ...)` -> `tracing::error!(error = ?err, ...)`.
  - Línea ~1523-1530 (`ScanSubmitError::Broker` dentro de su `impl IntoResponse`,
    el call site nombrado explícitamente por la descripción de la feature):
    `tracing::error!(error = %err, ...)` -> `tracing::error!(error = ?err, ...)`.
  - Ningún otro cambio: mensaje humano, `StatusCode` y cuerpo de ambas
    respuestas HTTP quedan exactamente iguales.
- `src/broker.rs`
  - Línea ~648-653 (`BrokerConsumer::run`, construye `BrokerError::ConsumeFailed`
    inline): `error = %BrokerError::ConsumeFailed { .. }` -> `error = ?BrokerError::ConsumeFailed { .. }`.
  - Añadidos 2 tests unitarios nuevos en `mod tests`:
    `publish_failed_display_never_changes_regardless_of_the_source_lapin_error`
    (congela el `Display` exacto y confirma que nunca incluye el detalle del
    `lapin::Error`) y `publish_failed_debug_includes_the_real_source_lapin_error`
    (confirma que el `Debug` derivado SÍ encadena el `lapin::Error` real vía
    `#[source]`).
  - Nota: los otros 3 `tracing::error!/warn!` cercanos (~líneas 665-670, 680-685,
    695-700, numeración tras la edición) loguean un `lapin::Error`/`serde_json::Error`
    **crudo** directamente, no un `BrokerError` envuelto — fuera de alcance,
    no se tocaron (confirmado antes de editar, documentado también en
    `progress/current.md`).
- `tests/scan_submission.rs`
  - Nuevo doble de prueba `AlwaysFailsToPublish` (siempre devuelve
    `BrokerError::PublishFailed { exchange: EXCHANGE_SCAN_REQUESTS, source: lapin::Error::ChannelsLimitReached }`).
  - Nuevo test de integración (sin Docker, corre en `cargo test` normal):
    `scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error`.
    Usa el stub feliz de `ms-usuarios` + el publicador que siempre falla, y
    verifica que `POST /api/scans` sigue respondiendo `502 Bad Gateway` con el
    cuerpo exacto `"no se pudo encolar la solicitud de escaneo"` — y que ese
    cuerpo **no** contiene `"ChannelsLimitReached"` (el detalle interno del
    `lapin::Error`, que ahora sí llega al log del servidor pero nunca a la
    respuesta HTTP).

## Verificación de los 4 criterios de aceptación

1. **Los 3 call sites agregan el `lapin::Error` real al log del servidor sin
   cambiar el `Display` expuesto a ningún llamante HTTP.**
   - Confirmado por lectura: `BrokerError` deriva `#[derive(Debug, thiserror::Error)]`
     (src/broker.rs:203) y `PublishFailed`/`ConnectionFailed`/`ConsumeFailed`
     anotan su `lapin::Error` con `#[source]` — el `Debug` derivado por
     `#[derive(Debug, ...)]` siempre imprime todos los campos de la variante
     (incluido `source`), así que `?err` SÍ incluye el `lapin::Error` real sin
     tocar el `impl Display` (hecho a mano vía `#[error("...")]`, que no cambió).
   - Confirmado también con los 2 tests unitarios nuevos en `src/broker.rs`
     (`publish_failed_display_never_changes_...` y
     `publish_failed_debug_includes_the_real_source_lapin_error`).
   - No usé el camino alternativo de recorrer `std::error::Error::source()` a
     mano porque el Debug derivado ya satisface el criterio de forma más simple
     y sin código adicional — documentado aquí por transparencia.

2. **`docs/security-scope.md` sigue siendo preciso.**
   - Releído completo antes de tocar código. Ya documentaba exactamente este
     patrón: "el detalle real solo en logs del lado del servidor (sin
     credenciales)" (sección "Rate limiting y superficie pública"). No fue
     necesario ningún cambio de texto — el documento ya cubría este caso.
   - Verifiqué además que `lapin::Error` (versión 2.5.5, fuente real en
     `~/.cargo/registry/.../lapin-2.5.5/src/error.rs`) nunca transporta la
     URL/credencial AMQPS: sus variantes son `ChannelsLimitReached`,
     `InvalidProtocolVersion`, `InvalidChannel(State)`, `IOError`,
     `ParsingError`, `ProtocolError`, `SerialisationError`,
     `MissingHeartbeatError` — ninguna incluye la URI de conexión. El `Debug`
     de `lapin::Error` es seguro de loguear.
   - El `Display` de `BrokerError` no se tocó en absoluto (ver tests nuevos).

3. **Test que confirma que `BrokerError::PublishFailed` sigue teniendo el
   mismo `Display`/contrato externo.**
   - `src/broker.rs::tests::publish_failed_display_never_changes_regardless_of_the_source_lapin_error`
     (unitario, congela el string exacto del `Display`).
   - `tests/scan_submission.rs::scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error`
     (integración HTTP end-to-end, confirma que `POST /api/scans` sigue
     devolviendo exactamente el mismo `502` + cuerpo que antes del fix).

4. **`cargo test` e `./init.sh` pasan en verde.**
   - Ver resultados de verificación abajo.

## Comandos de verificación ejecutados

- `cargo build` -> OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings` -> OK, sin warnings.
- `cargo fmt --check` -> OK, sin diferencias.
- `cargo test` -> OK, 67 unit tests + todos los tests de integración no
  marcados `#[ignore]` pasan (incluye el test nuevo
  `scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error`).
- `./init.sh` -> OK completo, incluidos los tests `--ignored` que requieren
  Docker (Docker estaba disponible en esta sesión): `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`,
  `cargo test -- --ignored`, `cargo doc --no-deps` — todos en verde. Resumen
  final: "Entorno listo. Puedes empezar a trabajar."

## Dudas o bloqueos

Ninguno. Fix mecánico y acotado, sin tocar ninguna otra feature ni el
`Display`/contrato HTTP de `BrokerError`.
