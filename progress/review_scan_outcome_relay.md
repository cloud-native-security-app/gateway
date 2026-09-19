# Review — feature 7 (scan_outcome_relay)

**Veredicto:** APPROVED

## Verificación ejecutada por el reviewer (no solo el informe del implementer)

- `cargo build` — OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings` — OK, sin warnings (incluye `tests/`).
- `cargo fmt --check` — sin diferencias.
- `cargo test` (sin `--ignored`) — 47 unitarios + 27 de integración no marcados, todos verdes; 2 marcados `#[ignore = "requiere Docker"]` (uno de esta feature, uno de `scan_submission`) omitidos correctamente.
- `cargo test -- --ignored` (Docker disponible) — ambos tests Docker pasan, incluido `tests/scan_outcome_relay.rs::consumes_scan_outcomes_from_a_real_queue_and_relays_them_via_sse_in_order_until_terminal_state`.
- `cargo doc --no-deps` — sin warnings.
- `./init.sh` — termina en verde (las 5 secciones, incluida la de Docker).
- `git status` — sin archivos sueltos sospechosos; el único cambio no explicado por el informe es `feature_list.json` (`status: pending -> in_progress` para id=7), que corresponde al protocolo de arranque del leader, no a una modificación del implementer.

## Criterios de aceptación (feature_list.json, id=7)

- **C1** — "`src/broker` consume `gateway.scan-outcomes`... y decodifica contra el schema": **[x]**. `BrokerConsumer::run` (`src/broker.rs:425-497`) usa `basic_consume` sin declarar topología (coherente con `configure: "^$"` del usuario `gateway`, documentado en el módulo y verificado en `progress/explore_lapin_consume.md` §4). `ScanOutcomeEvent` (`src/domain.rs`) refleja las 3 variantes `started`/`completed`/`failed` con `deny_unknown_fields`, con 7 tests unitarios de decodificación y verificación end-to-end contra RabbitMQ real en el test Docker.
- **C2** — "cada evento actualiza el estado... best-effort, no bloquea el ack ni el relay SSE": **[x]**. En `BrokerConsumer::run`, el `ack` (línea 460) ocurre *antes* de invocar `handler.handle(event)` (línea 466) — un fallo de `ms-usuarios` dentro de `wiring::ScanOutcomeRelay::handle` (`src/wiring.rs:165-176`) solo hace `tracing::error!` y retorna, nunca propaga ni bloquea. Verificado en el test Docker: `ms-usuarios` recibe `EN_PROGRESO` y `COMPLETADO` en orden para el `scan_id` correcto (líneas 627-645 de `tests/scan_outcome_relay.rs`).
- **C3** — "`GET /api/scans/{scan_id}/events` emite hasta un estado terminal y cierra ordenadamente": **[x]**. `RealtimeRegistry::subscribe_stream` (`src/realtime.rs:103-137`) usa `stream::unfold` con estado `Option<(Receiver, Guard)>`; al emitir un evento terminal el próximo estado es `None`, cerrando el `Stream`. Cubierto sin Docker por `realtime::tests::relays_events_in_order_and_closes_on_terminal_state` y end-to-end por el test Docker (líneas 596-623: recibe `started` → `completed` → `None`).
- **C4** — "solo la sesión dueña puede suscribirse": **[x]**. `scan_events` (`src/api.rs:340-358` aprox.) compara `ownership.owner.sub` contra `session.sub`; tanto ausencia como pertenencia ajena devuelven `404` idéntico (`ScanEventsError::NotFound`), evitando enumeración de scans ajenos. Cubierto por `sse_events_rejects_a_scan_id_owned_by_another_session` y `sse_events_rejects_an_unknown_scan_id` (sin Docker, ambos verdes).
- **C5** — "mensaje malformado se descarta con log (sin credenciales) y no tumba el consumidor": **[x]**. En el `Err` de `serde_json::from_slice` (`src/broker.rs:468-487`) se hace `tracing::warn!` con el error de deserialización, `routing_key` y `payload_len` — nunca `delivery.data` completo — y `nack(requeue: false)` (dead-letter inmediato, evita el problema documentado de `x-delivery-limit` no disparándose con `requeue: true`). El bucle `while let Some(delivery) = consumer.next().await` sigue vivo tras el `continue`/procesamiento del mensaje malformado. Verificado en el test Docker: se publica un JSON inválido *entre* `started` y `completed`, y el segundo evento SSE recibido es igualmente `completed` (el consumidor no se cayó ni se saltó el resto de la cola).
- **C6** — "tests de integración `#[ignore = \"requiere Docker\"]`: started/completed/failed en orden; scan_id de otro usuario rechazado; mensaje malformado no tumba el consumidor": **[x]**. Los 3 escenarios están cubiertos: el test Docker cubre orden de eventos + malformado + best-effort hacia `ms-usuarios`; los otros 2 tests (sin Docker, pero exigidos igualmente por el criterio) cubren el rechazo de scan_id ajeno/inexistente. Nombres descriptivos, consistentes con `docs/conventions.md`.

## Coherencia con la decisión de diseño de mapeo `correlation_id` -> `scan_id` de `ms-usuarios`

`ScanOwnershipRegistry` (`src/api.rs`) es exactamente el registro en memoria acordado con el usuario: `HashMap<String /* scanId propio */, ScanOwnership { ms_usuarios_scan_id, owner: Session }>` tras `RwLock`, poblado en `submit_scan` inmediatamente después de `create_scan_history` y consultado tanto por `scan_events` (autorización SSE) como por `wiring::ScanOutcomeRelay::handle` (para saber qué `scan_id` de `ms-usuarios` actualizar). La limitación de "vive solo en memoria del proceso, se pierde en un restart" está documentada explícitamente en el rustdoc de `ScanOwnershipRegistry`, con la misma redacción/patrón que ya se aceptó para `auth::LoginStateStore` — no hay sobre-ingeniería (no se implementó persistencia no pedida) ni inconsistencia con lo acordado.

## Confirmación: diff de `src/api.rs` sobre `submit_scan` (feature 6, ya cerrada)

Verificado con `git diff HEAD -- src/api.rs`: el único cambio dentro del cuerpo de `submit_scan` es la inserción de 3 líneas (`state.scan_ownership.register(&scan_id, history_entry.scan_id.clone(), session.clone());`) justo después de `create_scan_history`, con un comentario explicando el propósito. El resto de la función (validación IP/CIDR, resolución de credenciales, publicación en el Broker, marcado a `Fallido` en caso de fallo de publicación) permanece byte-a-byte igual al código ya aprobado en el commit `c6e27ac`. No se reabrió lógica de la feature 6.

## Credencial AMQPS y datos sensibles en logs

- Ningún log de `src/broker.rs`, `src/wiring.rs`, `src/realtime.rs`, `src/api.rs` (código nuevo/modificado de esta feature) incluye la URL/credencial AMQPS (`config.broker_amqps_url` nunca se referencia en un `tracing::*!`), ni `ssh_credentials_ref` (no forma parte de `ScanOutcomeEvent`/`ScanResult`, que solo modelan hallazgos de escaneo, no credenciales), ni la credencial de servicio hacia `ms-usuarios`, ni la sesión firmada completa.
- El log del mensaje malformado (`src/broker.rs:469-474`) usa explícitamente el error de `serde_json`, `routing_key` y `payload_len` — nunca `delivery.data` crudo — consistente con `docs/security-scope.md` y con el análisis de `progress/explore_lapin_consume.md` §3.4.
- `ScanRequest::Debug` (feature 6, reutilizado sin cambios) sigue redactando `ssh_credentials_ref` a mano.

## Evaluación de la expansión hacia `wiring`/`run()` real

**Veredicto: proporcional y necesaria, no es una expansión de alcance injustificada.**

Justificación:
1. `docs/architecture.md` §"Capas" ya prevé explícitamente la capa 8 (`wiring` — composition root) y la 9/10 (`lib::run()`/`main.rs` delgado) como parte de la arquitectura fijada desde el diseño original del repo — no es una capa inventada por el implementer, sino una que estaba documentada y pendiente de materializar.
2. La feature 1 (`scaffolding`) dejó `wiring` explícitamente diferido "para cuando una feature futura lo requiera explícitamente". La feature 7 es la primera que introduce una tarea de fondo (`BrokerConsumer::run`) que debe vivir durante todo el ciclo de vida del proceso, coexistiendo con `axum::serve` — esto es precisamente lo que un composition root real resuelve (construir ambas piezas desde `Config` y lanzarlas juntas). No hay forma de cumplir el criterio de aceptación 1/2 (consumidor de fondo corriendo) sin algún punto de arranque real del proceso.
3. El alcance de `wiring::build` está acotado a construir exactamente lo que las features ya aprobadas (1-6) y esta feature (7) necesitan: `OidcClient`, `UsuariosClient`, `BrokerPublisher`, `BrokerConsumer`, `ScanOwnershipRegistry`, `RealtimeRegistry`, y el `ScanOutcomeRelay` que las une — no se adelantó wiring de features futuras (rate limiting, OpenAPI, etc.).
4. `src/lib.rs::run()` pasó de un stub (`tracing::info!("starting")`) a un `run()` real con manejo de errores tipado (`RunError`, sin `unwrap`/`panic!`) y `main.rs` sigue siendo un envoltorio delgado (`tokio::main` + `tracing_subscriber::fmt::init()` + logging del error final) — coherente con `docs/architecture.md` §"Capas" punto 10.
5. No se observa una capa nueva no prevista: `CHECKPOINTS.md` C3 ya lista `wiring` entre los módulos previstos de `src/`.

## Checkpoints (CHECKPOINTS.md)

- C1 — [x] Los 4 archivos base y los 4 docs existen; `./init.sh` termina en verde (verificado directamente).
- C2 — [x] Como mucho una feature `in_progress` (id=7, la que corresponde a esta sesión); `progress/current.md` describe la sesión activa, sin basura de sesiones previas.
- C3 — [x] `src/` solo contiene los módulos previstos (incluido `wiring`, ya justificado arriba); toda dependencia nueva de `Cargo.toml` (`futures-util` movida a `[dependencies]`, `tokio` con `sync` explícito, `reqwest`+`bytes` en `[dev-dependencies]`) está justificada y documentada con comentarios en el propio `Cargo.toml`; sin `println!`/`dbg!`/`unwrap()`/`panic!()` fuera de tests en el código nuevo; `cargo doc --no-deps` sin warnings; ninguna feature inventó el shape de una API pendiente (el `ScanOutcomeEvent` es copia literal del contrato real, no especulativo, a diferencia de `resolve_scan_target` de la feature 6, que sigue correctamente marcado como especulativo).
- C4 — [x] Hay tests de integración por cada módulo que cruza IO relevante a esta feature (`broker`, `api`/SSE); los tests de `broker` corren contra RabbitMQ real vía `testcontainers` con la topología copiada de `broker/rabbitmq/definitions.json`; `cargo test` muestra > 0 tests y todos verdes; `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5 — [x] No hay archivos sin trackear sospechosos (los `??` de `git status` son exactamente los archivos que el informe del implementer describe como nuevos); pendiente de que el leader mueva `progress/current.md` a `progress/history.md` al cerrar la sesión (fuera del alcance de este reviewer); la feature id=7 queda correctamente reflejada como aprobable (el leader debe marcarla `done`, no lo hace este reviewer).

## Cambios requeridos

Ninguno.
