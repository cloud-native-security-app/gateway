# Implementación — feature 8: scan_history_and_cancellation

## Alcance

Únicamente la feature id=8 de `feature_list.json` (histórico y cancelación de
escaneos, `GET /api/scans` y `POST /api/scans/{scan_id}/cancel`). No se tocó
ninguna otra feature ni su `status` — sigue `in_progress` porque el
`leader`/`reviewer` son quienes la mueven a `done`.

## Archivos creados

- `tests/scan_history_and_cancellation.rs` — tests de integración de esta
  feature (histórico, cancelación propia/ajena/ya-terminada, con y sin
  Docker según el escenario).

## Archivos modificados

- `src/broker.rs`:
  - Nuevas constantes `EXCHANGE_SCAN_CANCELLATIONS` (`scan.cancellations`) y
    `ROUTING_KEY_SCAN_CANCELLATION` (`scan.cancellation`).
  - Nuevo tipo `ScanCancellation { correlation_id, requested_by }`, shape
    copiado literal de `broker/contracts/scan-cancellation.schema.json`
    (2 campos, `additionalProperties: false`); test unitario que verifica que
    solo esas 2 claves se serializan.
  - `ScanRequestPublisher` (el trait ya existente de la feature
    `scan_submission`) se **extiende** con un método nuevo,
    `publish_scan_cancellation`, en vez de crear un trait hermano nuevo — ver
    "Decisiones de diseño" abajo.
  - `BrokerPublisher` implementa el método nuevo reutilizando la misma
    conexión/canal AMQPS ya abierto (el usuario `gateway` ya tiene `write`
    sobre `scan.requests` y `scan.cancellations`). Se extrajo un helper
    privado `publish_and_confirm` para no duplicar la lógica de
    serializar+publicar+esperar el ack entre `publish_scan_request` y
    `publish_scan_cancellation`.
- `src/usuarios_client.rs`: nuevo método `list_scan_history` (`GET
  /users/me/scans`, misma URL que ya usaba `create_scan_history` pero con
  `GET`), reenviando los mismos headers `X-Forwarded-User`/`X-Gateway-Secret`
  ya establecidos. Mismo mapeo de errores que `get_profile`.
- `src/api.rs`:
  - `ScanOwnershipRegistry::lookup_by_ms_usuarios_scan_id` — lookup inverso
    (recorrido lineal documentado, no se añadió un segundo índice).
  - `GET /api/scans` (handler `list_scan_history`): proxea el histórico y
    traduce cada entrada a `ScanHistoryEntryResponse`, que añade un campo
    opcional `scanId` (el propio de este Gateway) vía el lookup inverso.
    Ausente (`skip_serializing_if`) si no hay mapeo conocido.
  - `POST /api/scans/:scan_id/cancel` (handler `cancel_scan`, sintaxis axum
    0.7 con `:scan_id`): verifica ownership contra la sesión activa (mismo
    patrón que `scan_events` de la feature 7, 404 uniforme si no existe o es
    ajeno), consulta `ms-usuarios` vía `list_scan_history` para conocer el
    estado actual del `scan_id` de `ms-usuarios` registrado en el
    `ScanOwnership`, y si es `Completado`/`Fallido` responde `409` sin
    publicar nada; en cualquier otro caso publica el `ScanCancellation`
    (`correlation_id` = `scan_id` del path — el propio de Gateway, nunca el
    de `ms-usuarios` — `requested_by` = `sub` de la sesión) y responde `202
    Accepted`.
  - Nuevas entradas en `ROUTES` (`GET /api/scans`, `POST
    /api/scans/:scan_id/cancel`, ambas protegidas) — el test de enumeración
    de rutas de la feature `session_middleware_and_me` las cubre
    automáticamente sin cambios en ese test.
- `tests/oidc_login.rs`, `tests/session_middleware_and_me.rs`,
  `tests/usuarios_profile_proxy.rs`, `tests/scan_submission.rs`,
  `tests/scan_outcome_relay.rs`: el doble de prueba `NeverPublishesToBroker`
  de cada uno ahora implementa también `publish_scan_cancellation`
  (panicking, mismo patrón ya usado para `publish_scan_request`), porque
  todos construyen un `AppState` con `broker_publisher: Arc<dyn
  ScanRequestPublisher>` y el trait ahora exige ese método.
- `tests/usuarios_client.rs`: 2 tests nuevos para `list_scan_history` (camino
  feliz contra un stub real, y `ms-usuarios` caído -> `Unreachable`).

## Decisiones de diseño

### 1. Extender `ScanRequestPublisher` en vez de un trait hermano

El prompt permitía ambas opciones. Elegí extender el trait existente (en vez
de crear `ScanCancellationPublisher` y un segundo campo en `AppState`) porque:

- Ambos métodos comparten exactamente la misma conexión/canal AMQPS y el
  mismo usuario RabbitMQ `gateway` (con permiso `write` sobre ambos
  exchanges) — no hay una razón de diseño para separarlos en dos objetos
  distintos.
- Añadir un segundo campo a `AppState` habría obligado a tocar los 6 archivos
  de test que construyen un `AppState` literal de todos modos (para añadir el
  campo), sin ganar nada a cambio de la separación de traits.
- El prompt explícitamente autorizaba "actualizar los dobles de prueba, como
  se hizo en features anteriores" — coherente con este camino.

Documenté esta decisión en el doc-comment del módulo (`src/broker.rs`), igual
que otras decisiones de diseño ya presentes ahí.

### 2. Cómo se determina el estado terminal antes de cancelar

`cancel_scan` llama a `UsuariosClient::list_scan_history` (el mismo método
que ya usa `GET /api/scans`) y busca la entrada cuyo `scan_id` coincide con
`ScanOwnership::ms_usuarios_scan_id`. Si el estado es `Completado`/`Fallido`,
responde `409 Conflict` sin publicar nada. Elegí esta vía (consultar a
`ms-usuarios`, no un estado local nuevo en `ScanOwnershipRegistry`/`AppState`)
porque:

- `ms-usuarios` ya es la fuente de verdad del histórico — lo actualiza el
  relay de `gateway.scan-outcomes` de la feature 7 en cada `ScanOutcome`
  consumido. Mantener un segundo estado local duplicaría esa fuente de verdad
  y podría desincronizarse (p. ej. si el relay actualiza `ms-usuarios` pero
  un estado local en memoria no se actualiza igual, o viceversa).
- Reutiliza un endpoint ya confirmado (`GET /users/me/scans`) en vez de
  inventar un endpoint de "un solo scan por id" que no está documentado.
- El costo es una llamada HTTP adicional antes de publicar la cancelación —
  aceptable para esta feature (no hay un requisito de latencia como el
  RNF-04 de `POST /api/scans`).

Si `ms-usuarios` no devuelve ninguna entrada con ese `scan_id` (debería ser
imposible en un flujo normal, dado que `ScanOwnership` solo se registra tras
un `create_scan_history` exitoso), se trata como una inconsistencia del lado
del servidor (`ScanCancelError::HistoryEntryMissing`, `502`), no como un
error del cliente.

### 3. Lookup inverso de `ScanOwnershipRegistry`

`lookup_by_ms_usuarios_scan_id` hace un recorrido lineal sobre el mismo
`HashMap` ya existente (`scanId propio -> ScanOwnership`), sin añadir un
segundo índice. Documentado igual que el resto del registro: el volumen
esperado es el de escaneos en curso de este proceso (no miles de entradas
históricas), así que no se justifica la complejidad de mantener un índice
inverso sincronizado.

### 4. Respuesta de `GET /api/scans`

`ScanHistoryEntryResponse` expone `target`/`status`/`requested_at`/
`updated_at` tal cual los reporta `ms-usuarios`, más `scanId` (propio de
Gateway, `Option<String>`, ausente en JSON vía `skip_serializing_if` si no
hay mapeo). Deliberadamente **no** expone el `scan_id` interno de
`ms-usuarios`: el cliente (`front`) solo necesita el `scanId` propio de
Gateway para el resto de la API (`GET /api/scans/{scan_id}/events`, `POST
/api/scans/{scan_id}/cancel`), y no hay razón para filtrar hacia `front` un
identificador de un microservicio interno (RF-09).

## Verificación de los 5 criterios de aceptación

1. **`GET /api/scans` devuelve el histórico proxeando a `ms-usuarios`**:
   verificado por
   `scan_history_returns_the_entries_of_the_active_session_with_and_without_known_scan_id`
   (`tests/scan_history_and_cancellation.rs`) — status `200`, 2 entradas con
   `target`/`status` correctos, más los tests de `usuarios_client.rs` para
   `list_scan_history` en sí (camino feliz + `ms-usuarios` caído).
2. **`POST /api/scans/{scan_id}/cancel` verifica ownership y publica un
   `ScanCancellation` válido en `scan.cancellations`**: verificado por
   `cancel_scan_owned_and_in_progress_publishes_a_valid_scan_cancellation`
   (`#[ignore = "requiere Docker"]`, corrido con éxito contra RabbitMQ real,
   ver más abajo) — responde `202`, y el mensaje consumido de la cola de
   verificación bindeada a `scan.cancellations`/`scan.cancellation` tiene
   exactamente `correlation_id` (= el `scanId` del path) y `requested_by`
   (= `sub` de la sesión), sin campos extra.
3. **Cancelar un scan ajeno o inexistente -> 404**: verificado por
   `cancel_scan_owned_by_another_session_returns_not_found` y
   `cancel_scan_that_does_not_exist_returns_not_found`, mismo status en
   ambos casos.
4. **Cancelar un scan ya terminado -> error explícito sin publicar**:
   verificado por
   `cancel_scan_already_in_a_terminal_state_is_rejected_without_publishing`
   (`409 Conflict`); el doble `NeverPublishesToBroker` habría hecho panic si
   el handler hubiera intentado publicar, y el test pasó sin panic.
5. **Tests de integración marcados `#[ignore = "requiere Docker"]` donde
   corresponde**: solo el escenario que publica de verdad en el Broker
   (`cancel_scan_owned_and_in_progress_publishes_a_valid_scan_cancellation`)
   está marcado así; los demás (histórico, 404 ajeno/inexistente, 409
   terminal) no tocan el Broker y corren en `cargo test` normal, mismo
   criterio que ya aplican `scan_submission`/`scan_outcome_relay`.

## Resultado de los comandos de verificación

- `cargo build` — sin warnings.
- `cargo clippy --all-targets -- -D warnings` — sin warnings.
- `cargo fmt --check` — sin diferencias (tras `cargo fmt`).
- `cargo test` (sin `--ignored`) — 48 unit tests + 4+8+5+3+2+3+3 = todos los
  tests de integración no-Docker de todas las features (1-8) en verde, `0`
  fallos.
- `cargo test -- --ignored` (Docker disponible en este entorno) — los 4 tests
  de integración con RabbitMQ real (features 6, 7 y el nuevo de la feature 8)
  pasan en verde.
- `cargo doc --no-deps` — genera sin errores (`#![deny(missing_docs)]`
  satisfecho para todo ítem público nuevo).
- `./init.sh` — termina con `[OK] Entorno listo. Puedes empezar a trabajar.`

## Dudas / bloqueos

Ninguno. Docker estaba disponible en este entorno, así que se corrieron y
verificaron también los tests `#[ignore]` (no quedó como verificación
pendiente).
