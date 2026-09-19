# Review — feature 8 (scan_history_and_cancellation)

**Veredicto:** APPROVED

## Verificación de comandos

- `cargo build` — sin warnings.
- `cargo fmt --check` — sin diferencias.
- `cargo clippy --all-targets -- -D warnings` — sin advertencias.
- `cargo test` (sin `--ignored`) — 48 unit + 4+2+2+5+8+3+3 tests de integración, todos `ok`, 0 fallos (incluye features 1-7, nada se rompió).
- `cargo test -- --ignored` (Docker disponible: `docker ps` respondió) — 4 tests con RabbitMQ real, incluido `cancel_scan_owned_and_in_progress_publishes_a_valid_scan_cancellation`, todos `ok`.
- `./init.sh` — termina en `[OK] Entorno listo. Puedes empezar a trabajar.` (exit 0).

## Criterios de aceptación (feature_list.json id=8)

1. **`GET /api/scans` devuelve el histórico del usuario de la sesión activa, proxeando a `ms-usuarios` vía `usuarios_client`** — PASA.
   `src/api.rs::list_scan_history` llama a `UsuariosClient::list_scan_history` (nuevo método en `src/usuarios_client.rs`, `GET /users/me/scans`), reenviando la identidad de sesión + `GATEWAY_SHARED_SECRET`. Confirmé contra `user-service/src/api.rs:98` que la ruta `GET /users/me/scans` (handler `list_scans`) existe de verdad en `user-service` — no es un endpoint inventado. Test `scan_history_returns_the_entries_of_the_active_session_with_and_without_known_scan_id` cubre el camino, más 2 tests nuevos de `usuarios_client.rs` (feliz + `ms-usuarios` caído).

2. **`POST /api/scans/{scan_id}/cancel` verifica ownership y publica un `ScanCancellation` válido (`correlation_id`=scan_id, `requested_by`=identidad de sesión) en `scan.cancellations`** — PASA.
   `cancel_scan` (`src/api.rs`) verifica `ScanOwnershipRegistry::lookup` + `ownership.owner.sub == session.sub` antes de publicar. `ScanCancellation { correlation_id, requested_by }` (`src/broker.rs`) coincide campo por campo con `broker/contracts/scan-cancellation.schema.json` (verificado leyendo el schema: 2 campos, `additionalProperties: false`). `correlation_id = scan_id` del path (el propio de Gateway, tomado directo del `Path` extractor, nunca el de `ms-usuarios`), `requested_by = session.sub` (identidad ya verificada, nunca un id reenviado sin validar). El test `#[ignore = "requiere Docker"]` `cancel_scan_owned_and_in_progress_publishes_a_valid_scan_cancellation` consume la cola real bindeada a `scan.cancellations`/`scan.cancellation` y confirma exactamente esos 2 campos — corrí este test y pasa.
   El usuario RabbitMQ `gateway` sí tiene `write` sobre `scan.cancellations` en `broker/rabbitmq/definitions.json` (confirmado: `'write': '^scan\\.(requests|cancellations)$'`), consistente con `docs/security-scope.md`.

3. **`scan_id` ajeno o inexistente -> 404 uniforme** — PASA.
   `ScanCancelError::NotFound` cubre ambos casos con el mismo status y mensaje genérico (mismo patrón que `ScanEventsError::NotFound` de la feature 7). Tests `cancel_scan_owned_by_another_session_returns_not_found` y `cancel_scan_that_does_not_exist_returns_not_found` confirman `404` en ambos, sin distinguir el motivo en la respuesta.

4. **`scan_id` en estado terminal -> error explícito sin publicar** — PASA.
   `cancel_scan` consulta `list_scan_history`, busca la entrada por `ms_usuarios_scan_id` y si el estado es `Completado`/`Fallido` devuelve `ScanCancelError::AlreadyTerminal` (`409`) antes de tocar `state.broker_publisher`. El doble `NeverPublishesToBroker` (usado en el test `cancel_scan_already_in_a_terminal_state_is_rejected_without_publishing`) hace `panic!` si `publish_scan_cancellation` se invoca — el test pasa sin panic, confirmando que no se publicó nada.

5. **Tests marcados `#[ignore = "requiere Docker"]` donde corresponde, y cubren los 4 escenarios** — PASA.
   Solo el escenario que publica de verdad en el Broker está marcado `#[ignore]`; histórico, 404 ajeno/inexistente y 409 terminal corren sin Docker. Los 5 tests de `tests/scan_history_and_cancellation.rs` cubren exactamente los 4 escenarios pedidos (+ el caso extra de histórico con/sin `scanId` conocido dentro del mismo test).

## Evaluación de las decisiones de diseño

- **Extender `ScanRequestPublisher` con `publish_scan_cancellation` en vez de un trait hermano**: razonable. Ambos métodos comparten conexión/canal/usuario RabbitMQ; separar en dos traits habría forzado un segundo campo en `AppState` sin beneficio de aislamiento real (el mismo usuario `gateway` tiene `write` sobre ambos exchanges). Los 5 dobles de prueba de features 1-7 (`NeverPublishesToBroker` en `oidc_login.rs`, `scan_outcome_relay.rs`, `scan_submission.rs`, `session_middleware_and_me.rs`, `usuarios_profile_proxy.rs`) fueron actualizados para implementar el método nuevo — verifiqué el diff de los 5 archivos, todos con panic explícito, sin ningún doble roto en silencio (habría fallado en compilación, no en runtime, dado que el trait ya no es `dyn`-object-safe sin el método completo).

- **Lookup inverso lineal en `ScanOwnershipRegistry` (`lookup_by_ms_usuarios_scan_id`)**: razonable dado el volumen esperado (escaneos en curso de un proceso, no histórico completo), documentado explícitamente como tal en el doc-comment, coherente con la limitación ya aceptada de `ScanOwnershipRegistry` (memoria de proceso, no persistente). `scanId` ausente (`Option<String>`, `skip_serializing_if`) en vez de excluir la entrada — coincide exactamente con la decisión que el líder documentó en `progress/current.md` y confirmé contra el schema (`correlation_id` = "el correlation_id del ScanRequest").

- **Determinar estado terminal consultando `ms-usuarios` (`list_scan_history`) en vez de un estado local**: razonable y es la opción preferida sugerida por el líder. Evita una segunda fuente de verdad que podría desincronizarse del relay de `scan_outcome_relay` (feature 7). Costo aceptado explícitamente (una llamada HTTP extra antes de publicar) — no hay un RNF-04 equivalente para `cancel`. Si `ms-usuarios` no devuelve ninguna entrada con el `ms_usuarios_scan_id` esperado, se trata como `502` (`HistoryEntryMissing`), no como error de cliente — razonable.

- **No se duplicó la actualización de estado de `ms-usuarios`**: confirmé con `grep "update_scan_status"` que la única llamada a ese método sigue viviendo en `submit_scan` (rollback a `Fallido` de la feature 6) — `cancel_scan` nunca lo invoca, tal como exige el contexto de esta review.

- **`GET /api/scans` no expone el `scan_id` interno de `ms-usuarios`**: correcto según RF-09 (no revelar identificadores de microservicios internos a `front`) — solo expone el `scanId` propio de Gateway.

## Seguridad

- Ningún log ni cuerpo de error incluye: token de Google, sesión firmada, `GATEWAY_SHARED_SECRET`, ni la credencial AMQPS. `ScanCancellation` no transporta ninguna credencial (confirmado contra el schema, que no incluye `ssh_credentials_ref` en este mensaje).
- `requested_by` siempre es `session.sub` (identidad ya verificada por el middleware de sesión), nunca un valor tomado del body/query del cliente — cumple RNF `no reenviar un identificador de usuario que no sea el de la sesión ya verificada`.
- `/api/scans` y `/api/scans/:scan_id/cancel` están dentro de `protected_router` (bajo `middleware::from_fn_with_state(validator, auth::require_session)`), y el test `enumerates_routes_and_verifies_which_carry_the_session_middleware` (de la feature 4, sin cambios) sigue pasando y cubre las 2 rutas nuevas automáticamente vía `ROUTES` — RF-10 cumplido, ninguna ruta protegida quedó accesible sin el middleware.

## Checkpoints relevantes (CHECKPOINTS.md)

- C1 (arnés completo, `./init.sh` exit 0): [x]
- C2 (una sola feature `in_progress`: id=8; `progress/current.md` describe la sesión activa sin basura): [x]
- C3 (módulos previstos, sin `println!`/`dbg!`/`unwrap`/`panic!` fuera de tests sin justificar, `cargo doc` sin warnings, ninguna API pendiente inventada — `GET /users/me/scans` confirmado real en `user-service/src/api.rs`): [x]
- C4 (tests de integración cruzando IO para `broker`/`usuarios_client`/`api`, RabbitMQ real vía `testcontainers` con topología copiada de `definitions.json`, `cargo test`/`clippy` verdes): [x]
- C5 (sin archivos sin trackear sospechosos — solo el test file y el progress file nuevos, esperados; última feature reflejada como `in_progress`, correcto porque el cierre a `done` lo hace el reviewer/leader, no el implementer): [x]

## Cambios requeridos

Ninguno.
