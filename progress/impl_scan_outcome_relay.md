# Implementación: feature 7 — `scan_outcome_relay`

## Archivos creados

- `src/wiring.rs` — composition root (capa 8 de `docs/architecture.md`, no
  implementada por ninguna feature anterior): `wiring::build(config) ->
  Wiring` construye `OidcClient`, `UsuariosClient`, `BrokerPublisher`,
  `BrokerConsumer`, `ScanOwnershipRegistry`, `RealtimeRegistry` y el
  `ScanOutcomeRelay` (impl privada de `ScanOutcomeHandler`) que une
  consumidor -> `ms-usuarios` + SSE.
- `tests/scan_outcome_relay.rs` — 2 tests sin Docker (rechazo de `scan_id`
  ajeno/desconocido en el SSE) + 1 test `#[ignore = "requiere Docker"]`
  (flujo completo contra RabbitMQ real).

## Archivos modificados

- `src/domain.rs`: `ScanOutcomeEvent` (enum `started`/`completed`/`failed`,
  tag `status`, `deny_unknown_fields`), `ScanResult`/`PortFinding`/
  `VulnFinding` (copiados literalmente de
  `broker/contracts/scan-outcome.schema.json`), `correlation_id()`/
  `is_terminal()`. +7 tests unitarios (decodifica cada variante, rechaza
  status desconocido/campos extra/campos faltantes).
- `src/broker.rs`: refactor de la conexión AMQPS compartida
  (`connect_channel`, usada tanto por `BrokerPublisher` como por el nuevo
  `BrokerConsumer`); `BrokerConsumer::run` consume `gateway.scan-outcomes`
  (sin declarar cola/binding, coherente con permisos `configure: "^$"` del
  usuario `gateway`), decodifica cada mensaje, hace `ack` en éxito y
  `nack(requeue: false)` en fallo de deserialización (log sin payload
  crudo: solo el error de `serde_json`, `routing_key`, tamaño en bytes);
  trait `ScanOutcomeHandler` como puente hacia capas superiores; nueva
  variante `BrokerError::ConsumeFailed`.
- `src/realtime.rs`: `RealtimeRegistry` (`HashMap<scan_id,
  broadcast::Sender<ScanOutcomeEvent>>` tras `RwLock`), `publish`,
  `subscribe_stream` (construye el `Stream<Item=Result<Event,Infallible>>`
  vía `stream::unfold`, cierre ordenado en estado terminal,
  `SubscriptionGuard` con `Drop` para limpiar el registro tanto en cierre
  ordenado como en desconexión temprana del cliente). +3 tests unitarios.
- `src/api.rs`: `ScanOwnershipRegistry`/`ScanOwnership` (nuevo, ver
  decisión de diseño abajo); `AppState` extendido con `scan_ownership` y
  `realtime`; `submit_scan` (feature `scan_submission`, ya aprobada) recibe
  **una única línea añadida** (`state.scan_ownership.register(...)`) justo
  después de `create_scan_history`, sin tocar el resto de su lógica; nuevo
  handler `scan_events` (`GET /api/scans/:scan_id/events`, sintaxis de ruta
  axum 0.7) + `ScanEventsError` (404 tanto para `scan_id` inexistente como
  ajeno, sin distinguir la respuesta); ruta añadida a `protected_router` y
  a la tabla `ROUTES`.
- `src/lib.rs`: `pub mod wiring;`, `run()` ahora carga `Config`, llama a
  `wiring::build`, lanza `tokio::spawn(consumer.run(handler))` y sirve
  `axum::serve` (antes era un stub `tracing::info!("starting")` sin
  servidor real — ninguna feature anterior lo necesitaba). Nuevo
  `RunError`.
- `src/main.rs`: maneja el `Result` de `run()` (loggea y
  `std::process::exit(1)` en vez de silenciar el error).
- `Cargo.toml`: `futures-util` movida a `[dependencies]` (ya se usa en
  producción: `Consumer::next()` y `stream::unfold`); `tokio` con feature
  `sync` explícito; `reqwest`+`bytes` añadidos a `[dev-dependencies]` para
  `bytes_stream()` en el test SSE.
- `tests/oidc_login.rs`, `tests/session_middleware_and_me.rs`,
  `tests/usuarios_profile_proxy.rs`, `tests/scan_submission.rs`: añadidos
  los 2 campos nuevos de `AppState` (`scan_ownership`, `realtime`) a cada
  construcción existente.

## Decisiones de diseño relevantes

1. **Registro de mapeo `correlation_id` -> (`scan_id` de `ms-usuarios`,
   sesión dueña)**: `ScanOwnershipRegistry` en `src/api.rs` (no en
   `broker.rs` ni en un módulo nuevo), porque lo puebla `submit_scan` y lo
   consultan tanto el handler SSE como el puente
   `wiring::ScanOutcomeRelay`. Mismo patrón que `auth::LoginStateStore`:
   estado en memoria del proceso, documentado como limitación aceptada (se
   pierde en un restart, no se comparte entre instancias).
2. **Ack/nack**: el mensaje se `ack`ea en cuanto decodifica con éxito
   contra `ScanOutcomeEvent` — *antes* de invocar al `handler` — para que
   un fallo de `ms-usuarios` nunca bloquee el ack ni el relay SSE
   (criterio de aceptación 2, best-effort). Un mensaje que no decodifica
   se `nack(requeue: false)` (dead-letter inmediato hacia
   `gateway.scan-outcomes.dlq`, ya aprovisionada por
   `broker/rabbitmq/definitions.json`) y se loggea sin el payload crudo.
3. **Cierre del stream SSE**: `RealtimeRegistry::subscribe_stream` usa
   `stream::unfold` con estado `Option<(Receiver, SubscriptionGuard)>`;
   al llegar a un evento terminal el próximo estado es `None` (cierre
   ordenado); si el cliente se desconecta antes, el `Drop` del guard
   limpia igual el registro. No se declaró ningún timer/keep-alive
   adicional (no lo exige ningún criterio de aceptación).
4. **Autorización del SSE**: `scan_events` compara `ownership.owner.sub`
   contra la sesión activa; tanto un `scan_id` inexistente como uno ajeno
   responden `404` idéntico (no se distingue la respuesta, mismo criterio
   que se documenta para la feature 8, cancelación).
5. **Wiring/composition root**: no existía ningún bootstrap real de
   `axum::serve` en el repo (todas las features anteriores construían su
   propio `AppState`+router solo en tests). Como esta feature exige que el
   consumidor de fondo "viva durante toda la vida del proceso", se
   implementó `src/wiring.rs` + `lib::run()` real, tal como sugiere
   `docs/architecture.md` (capa 8, ya prevista, no una capa nueva
   inventada). Errores tipados (`RunError`/`WiringError`) sin panics; el
   proceso termina con código de salida 1 y loggea el motivo si el arranque
   falla.
6. **Sin reconexión automática del consumidor**: documentado explícitamente
   en `src/broker.rs` (mismo criterio que ya aplicó `scan_submission` al
   publicador): si el stream de `lapin` se agota, la tarea loggea y
   termina; la recuperación es responsabilidad del orquestador del proceso,
   no de este módulo.

## Verificación de los 6 criterios de aceptación

1. **Consume `gateway.scan-outcomes` (bindeada a `scan.outcome.#`) y
   decodifica contra el schema real** — `BrokerConsumer::run`
   (`src/broker.rs`) + `ScanOutcomeEvent` (`src/domain.rs`, copiado
   literal de `broker/contracts/scan-outcome.schema.json`). Verificado con
   7 tests unitarios de decodificación (`domain::tests`) y con el test
   Docker que publica las 3 variantes reales en la cola.
2. **Cada evento actualiza el estado en `ms-usuarios`, best-effort** —
   `wiring::ScanOutcomeRelay::handle` llama a
   `UsuariosClient::update_scan_status` tras el `ack`; un error se loggea
   sin propagarse. Verificado en el test Docker: el stub de `ms-usuarios`
   capturó `EN_PROGRESO` y luego `COMPLETADO` para el `ms_usuarios_scan_id`
   correcto, y el mensaje malformado (que no llega a `handle`) no generó
   ninguna llamada.
3. **`GET /api/scans/{scan_id}/events` emite eventos hasta un estado
   terminal y cierra ordenadamente** — `RealtimeRegistry::subscribe_stream`
   + handler `scan_events` (`src/api.rs`). Verificado con
   `realtime::tests::relays_events_in_order_and_closes_on_terminal_state`
   (sin Docker) y con el test Docker end-to-end (SSE real vía `reqwest`,
   confirma orden `started` -> `completed` y cierre `None` tras el
   terminal).
4. **Solo la sesión dueña puede suscribirse** —
   `tests/scan_outcome_relay.rs::sse_events_rejects_a_scan_id_owned_by_another_session`
   y `::sse_events_rejects_an_unknown_scan_id` (ambos `404`, sin Docker).
5. **Mensaje malformado se descarta con log, sin tumbar el consumidor** —
   verificado en el test Docker: se publica un mensaje malformado *entre*
   `started` y `completed`; el segundo evento SSE sigue siendo `completed`
   (el consumidor no se cayó ni se saltó el resto de la cola). El log usa
   `tracing::warn!` con el error de deserialización, `routing_key` y
   tamaño en bytes — nunca el payload completo.
6. **Tests de integración `#[ignore = "requiere Docker"]`** —
   `tests/scan_outcome_relay.rs::consumes_scan_outcomes_from_a_real_queue_and_relays_them_via_sse_in_order_until_terminal_state`,
   marcado y verificado tanto con `cargo test` (se omite) como con
   `cargo test -- --ignored` (pasa, Docker disponible en esta sesión).

## Resultado de los comandos de verificación

- `cargo build` — OK.
- `cargo build --all-targets` — OK (2 warnings de imports no usados en el
  primer intento del test nuevo, corregidos).
- `cargo fmt --check` — sin diferencias.
- `cargo clippy --all-targets -- -D warnings` — sin warnings.
- `cargo test` (sin `--ignored`) — 47 unitarios + 25 de integración no
  marcadas `#[ignore]`, todos verdes; los 2 tests que requieren Docker
  quedan `ignored` como se espera.
- `cargo test -- --ignored` — Docker disponible en esta sesión: ambos tests
  Docker (el nuevo de esta feature y el ya existente de `scan_submission`)
  pasan.
- `cargo doc --no-deps` — sin warnings (se corrigieron 2 avisos de
  `rustdoc::private_intra_doc_links` iniciales, enlaces a ítems privados
  reescritos como texto con backticks).
- `./init.sh` — `[OK] Entorno listo. Puedes empezar a trabajar.` (todas las
  secciones en verde, incluida la 4 con Docker disponible).

## Dudas / bloqueos

Ninguno. No se tocó ninguna otra feature de `feature_list.json` ni su
`status` (sigue `in_progress`, a la espera del veredicto del reviewer).
