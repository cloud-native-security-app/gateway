# Review — feature 19 (log_broker_publish_errors)

**Veredicto:** APPROVED

## Criterios de aceptación (feature_list.json id=19)

1. **Los 3 call sites loguean con `?err`/Debug en vez de `%err`/Display, sin cambiar `Display` ni respuesta HTTP — PASA.**
   - `src/api.rs:904` (`ScanCancelError::Broker`) y `src/api.rs:1531` (`ScanSubmitError::Broker`): confirmado por diff, `%err` -> `?err`, sin tocar `StatusCode::BAD_GATEWAY` ni el texto del cuerpo (`"no se pudo encolar la cancelación del escaneo"` / `"no se pudo encolar la solicitud de escaneo"`).
   - `src/broker.rs:654-655` (`BrokerConsumer::run`): `error = %BrokerError::ConsumeFailed{..}` -> `error = ?BrokerError::ConsumeFailed{..}`, mismo patrón, este call site no produce respuesta HTTP.
   - Confirmado leyendo `enum BrokerError` (`src/broker.rs:203-236`): deriva `#[derive(Debug, thiserror::Error)]` y `ConnectionFailed`/`PublishFailed`/`ConsumeFailed` anotan su `lapin::Error` con `#[source]` — el Debug derivado SÍ encadena esa causa, el `#[error(...)]` (Display) no cambió.
   - Respaldado por 2 tests unitarios nuevos en `src/broker.rs::tests` (`publish_failed_display_never_changes_regardless_of_the_source_lapin_error`, `publish_failed_debug_includes_the_real_source_lapin_error`) que verifiqué leyendo el código: el primero congela el `Display` exacto y afirma que NO contiene `"ChannelsLimitReached"`; el segundo afirma que el `Debug` SÍ lo contiene.
   - **Scope correcto confirmado**: los otros `tracing::error!/warn!` en `src/broker.rs` (líneas 666, 677, 685, 698, 707) **no fueron tocados** — loguean un `lapin::Error`/`serde_json::Error` crudo directamente (no un `BrokerError` envuelto), fuera del alcance de la feature tal como documenta el implementer y `progress/current.md`. Sin scope creep.

2. **`docs/security-scope.md` sigue siendo preciso — PASA.**
   - `git diff docs/security-scope.md` está vacío: no hubo cambios. El documento ya cubre este patrón ("el detalle real solo en logs del lado del servidor (sin credenciales)", sección "Rate limiting y superficie pública"). El `Display` de `BrokerError` no cambió en el diff. No se detectó ninguna filtración nueva de la URL/credencial AMQPS hacia logs o respuestas HTTP.

3. **Test que confirma que el `Display`/contrato HTTP externo de un `BrokerError::PublishFailed` simulado no cambió — PASA.**
   - Unitario: `src/broker.rs::tests::publish_failed_display_never_changes_regardless_of_the_source_lapin_error`.
   - Integración end-to-end: `tests/scan_submission.rs::scan_submission_broker_publish_failure_response_is_unchanged_when_logging_the_real_error`, con el doble `AlwaysFailsToPublish` (siempre devuelve `BrokerError::PublishFailed{..., source: lapin::Error::ChannelsLimitReached}`). Verifica `POST /api/scans` -> `502 Bad Gateway`, cuerpo exacto `"no se pudo encolar la solicitud de escaneo"`, y que el cuerpo NO contiene `"ChannelsLimitReached"`. Pasa en `cargo test` normal (no requiere Docker).

4. **`cargo test` e `./init.sh` pasan en verde — PASA.**
   - Verificado de forma independiente (no solo confiando en el reporte):
     - `cargo build` -> OK, sin warnings.
     - `cargo clippy --all-targets -- -D warnings` -> OK, sin warnings.
     - `cargo fmt --check` -> OK, sin diferencias.
     - `cargo test` -> todo verde (incluye el test nuevo de `scan_submission.rs`); tests que requieren Docker correctamente marcados `#[ignore]`.
     - `./init.sh` completo (Docker disponible en esta sesión) -> verde de punta a punta, incluidos los tests `--ignored` (`broker_publisher_reconnect`, `scan_history_and_cancellation`, `scan_outcome_relay`, `scan_submission` con contenedor RabbitMQ real) y `cargo doc --no-deps` sin warnings. Resumen final: "Entorno listo. Puedes empezar a trabajar."

## Checkpoints relevantes (CHECKPOINTS.md)

- C1 (`./init.sh` exit 0): [x]
- C3 (arquitectura: sin módulos nuevos, sin `println!`/`dbg!`/`unwrap()` nuevos, cambio mecánico dentro de `api`/`broker`): [x] — diff revisado línea por línea, es exactamente `%err` -> `?err` más comentarios explicativos y 2 tests nuevos; no se tocó la firma de `BrokerError`, ni se introdujo ningún campo/API inventada.
- C4 (`cargo test` > 0 y verde, `cargo clippy` sin warnings): [x]

## Otras verificaciones hechas

- Diff de `feature_list.json`: solo cambia `status` de `pending` a `in_progress` para id=19, consistente con el flujo del leader (el reviewer no marca `done`).
- Archivo untracked `.atl/` es tooling ajeno (skill registry cache), no código del implementer.
- No se filtra el token de Google, la sesión firmada, la credencial de `ms-usuarios` ni la credencial AMQPS en ningún log o respuesta HTTP tocado por este cambio.
- RF-10 (middleware de sesión): no aplica a este fix, ninguna ruta nueva fue introducida ni modificada en su protección.

## Cambios requeridos

Ninguno.
