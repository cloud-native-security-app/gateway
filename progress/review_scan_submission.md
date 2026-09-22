# Review — feature 6 (scan_submission)

**Veredicto:** APPROVED

## Verificación de comandos

- `cargo build` — OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings` — OK, sin advertencias (incluye `tests/`).
- `cargo fmt --check` — OK, sin diferencias.
- `cargo test` (sin `--ignored`) — 38 tests unitarios + 25 tests de integración en verde
  (incluye los 3 nuevos de `tests/scan_submission.rs` que no requieren Docker); el test
  `#[ignore]` aparece listado como `ignored` tal como se espera. Nada de las features 1-5
  se rompió.
- `cargo test -- --ignored` (Docker disponible) —
  `scan_submission_happy_path_publishes_a_valid_scan_request_and_returns_the_scan_id`
  pasa contra `rabbitmq:4.3.5-management` real vía `testcontainers`. Sin contenedores
  huérfanos tras la corrida (`docker ps -a` verificado, ninguno de rabbitmq).
- `./init.sh` — termina `[OK] Entorno listo` (exit code 0), incluida la sección de Docker.

## Criterios de aceptación (feature_list.json, id=6)

1. **400 sin tocar ms-usuarios ni el Broker con IP/CIDR inválido** — PASA.
   `ScanSubmission::parse` (`src/domain.rs:71-91`) corre antes de cualquier `.await`
   externo en `submit_scan` (`src/api.rs:208`, primera línea del handler). Verificado con
   `scan_submission_rejects_invalid_target_without_touching_ms_usuarios_or_broker`
   (`tests/scan_submission.rs:319-346`), que apunta `ms_usuarios_base_url` a un puerto sin
   nada escuchando y `broker_publisher` a `NeverPublishesToBroker` (hace `panic!` si se
   invoca) — el test pasa, así que ninguno de los dos se tocó.

2. **`scanId`/`correlation_id` propio antes de cualquier llamada externa** — PASA.
   `src/api.rs:210` (`uuid::Uuid::new_v4()`) se ejecuta inmediatamente después de
   `ScanSubmission::parse` y antes de `resolve_scan_target` (línea 214), la primera
   llamada externa del handler. Ver evaluación de la decisión de diseño más abajo.

3. **Error explícito 501/422 si la API de credenciales no existe/no hay
   configuración, nunca un valor inventado** — PASA. `resolve_scan_target`
   (`src/usuarios_client.rs:379-411`) distingue `404` → `ScanTargetResolutionNotImplemented`
   y `422` → `ScanTargetNotConfigured`; `IntoResponse for UsuariosClientError`
   (`src/api.rs:444-470`) los mapea a `501`/`422` respectivamente. No hay ninguna rama que
   sustituya un valor por defecto/inventado — confirmado leyendo el método completo.
   Cubierto por
   `scan_submission_returns_an_explicit_error_when_ms_usuarios_scan_target_api_is_unavailable`
   y
   `scan_submission_returns_an_explicit_error_when_ms_usuarios_has_no_credentials_configured`
   (ambos en verde).

4. **Histórico + ScanRequest publicado contra el schema real cuando los 3 campos se
   resuelven** — PASA. `ScanRequest` (`src/broker.rs:64-84`) tiene exactamente los 6
   campos de `broker/contracts/scan-request.schema.json`
   (`correlation_id`/`ip`/`network_user`/`ssh_credentials_ref`/`has_sudo`/
   `requested_by`), confirmado además por el test
   `scan_request_serializes_with_the_exact_contract_fields` y, en el camino feliz con
   Docker, por la aserción `scan_request.len() == expected_keys.len()`
   (`tests/scan_submission.rs:606-618`) contra un mensaje real consumido de la cola de
   verificación. `create_scan_history` se llama antes de construir el `ScanRequest`
   (`src/api.rs:217-229`).

5. **Respuesta HTTP sin esperar desenlace del escaneo** — PASA. `submit_scan` no
   suscribe ni consume `gateway.scan-outcomes`; responde en cuanto retorna el `.await`
   de `publish_scan_request` (`src/api.rs:231-250`). `src/broker.rs` documenta
   explícitamente que el consumidor de `gateway.scan-outcomes` es responsabilidad de la
   feature `scan_outcome_relay`, fuera de alcance aquí.

6. **Fallo de publish tras histórico registrado → `Fallido`, nunca `Pendiente`
   huérfano** — PASA. `src/api.rs:231-248`: si `publish_scan_request` falla, se llama a
   `update_scan_status(..., ScanStatus::Fallido)` con `history_entry.scan_id` (el
   identificador real de `ms-usuarios`, no el `correlation_id` propio) antes de devolver
   el error; un fallo de esa compensación se loggea (`tracing::error!`) sin ocultar el
   error original. No hay un test de integración dedicado para esta rama específica —
   pero el criterio de aceptación #7 no la exige explícitamente como escenario de test
   (enumera solo: inválido→400, ms-usuarios no disponible→error explícito, camino
   feliz), así que no es un incumplimiento de acceptance, solo un hueco de cobertura
   marcado honestamente por el implementer en su informe. No bloquea.

7. **Los 4 tests descritos existen y cubren los escenarios** — PASA. Los 3 escenarios
   sin Docker corren en `cargo test` normal; el camino feliz corre en
   `cargo test -- --ignored` contra RabbitMQ real con la topología copiada literal de
   `broker/rabbitmq/definitions.json` (confirmado con `diff` byte a byte contra
   `broker/rabbitmq/{definitions.json,rabbitmq.conf,tls/*.pem}` — sin diferencias).

## Evaluación de la decisión: dos identificadores distintos para un mismo escaneo

Confirmé directamente contra `user-service/src/api.rs` (líneas 218-243) que
`POST /users/me/scans` **no acepta** un `scan_id` externo: lo genera internamente
(`Uuid::new_v4()`, comentario explícito "`scan_id` lo genera este servicio, nunca el
llamante"). El criterio de aceptación #2 exige literalmente generar el `scanId` propio
"antes de cualquier llamada externa", lo cual es incompatible con intentar forzar que
`ms-usuarios` use ese mismo valor.

La resolución del implementer (UUID propio como `scanId`/`correlation_id`, guardando el
`scan_id` de `ms-usuarios` solo para la compensación) es razonable:

- No inventa ni el shape de una API pendiente ni una credencial — es una decisión de
  identificadores internos, no toca el vacío de diseño documentado en
  `docs/architecture.md` §"Dependencia pendiente".
- Cumple el criterio de aceptación #2 literalmente (el UUID se genera antes de
  `resolve_scan_target`, la primera llamada externa).
- Está documentada en tres lugares coherentes: doc-comment de
  `UsuariosClient::create_scan_history` (`src/usuarios_client.rs:294-305`), el
  doc-comment de `submit_scan` (`src/api.rs:183-202`), y
  `progress/impl_scan_submission.md` §"Decisiones de diseño" con una nota explícita para
  la feature futura `scan_outcome_relay` (necesitará mapear `correlation_id` →
  `scan_id` real).
- No es una ambigüedad de seguridad ni una interpretación audaz de
  `docs/security-scope.md`/`docs/architecture.md`: es una tensión entre un criterio de
  aceptación y un contrato externo ya confirmado (no especulativo, a diferencia del
  endpoint de `scan-targets`). Bloquear aquí para preguntar al usuario habría sido
  desproporcionado — la única alternativa real sería reinterpretar el criterio #2 (no
  autorizado) o inventar una extensión de la API de `ms-usuarios` para aceptar un
  `scan_id` externo (expresamente prohibido por `docs/architecture.md` §"Qué NO hacer").

**Veredicto sobre esta decisión: aceptable tal cual quedó documentada.** El reviewer no
exige que se bloquee ni se pregunte al usuario; sí exige (y aquí se cumple) que la
consecuencia para `scan_outcome_relay` quede registrada explícitamente para que esa
feature futura no asuma que `correlation_id == scan_id`.

## Seguridad (docs/security-scope.md)

- `ssh_credentials_ref` nunca aparece en un log: `grep` dirigido no encontró ninguna
  ocurrencia junto a `trace!/debug!/info!/warn!/error!`. `ScanRequest` y
  `ScanTargetCredentials` implementan `Debug` a mano redactando el campo
  (`src/broker.rs:86-97`, `src/usuarios_client.rs:142-150`), con test que lo verifica en
  ambos casos.
- La credencial AMQPS nunca se loggea: `build_amqps_uri` (que interpola la credencial en
  la URI) solo se usa para pasarla a `Connection::connect_with_config`
  (`src/broker.rs:197-202`), nunca se imprime. Todos los `tracing::*!` de `BrokerError`
  usan `%err` (Display, mensajes fijos de `thiserror` sin interpolar el `#[source]`
  `lapin::Error`), nunca `{:?}` sobre `BrokerError` — evita que un eventual `Debug` de
  `lapin::Error` (que sí podría incluir la URI) se filtre a los logs.
- `src/broker.rs` no redeclara topología: solo llama a `basic_publish`
  (`ScanRequestPublisher::publish_scan_request`), nunca a `exchange_declare`/
  `queue_declare`/`queue_bind` — confirmado con `grep`. La declaración de la cola de
  verificación con el usuario `lab-admin` vive exclusivamente en
  `tests/scan_submission.rs` (líneas 456-533), consistente con que el usuario `gateway`
  solo tiene `configure: "^$"` en `broker/rabbitmq/definitions.json`.
- Ninguna respuesta de error expone URL/credencial interna: los mensajes de
  `UsuariosClientError`/`BrokerError` son genéricos y fijos (test
  `error_messages_never_include_the_base_url` lo confirma para el primero); ninguno
  interpola datos de `ms-usuarios`/Broker.
- `POST /api/scans` está dentro de `protected_router` (`src/api.rs:85-101`), bajo el
  middleware `auth::require_session`, y aparece como `protected: true` en la tabla
  canónica `ROUTES` (`src/api.rs:307-311`), verificada además por el test de enumeración
  ya existente `enumerates_routes_and_verifies_which_carry_the_session_middleware`
  (sigue en verde). Ninguna ruta protegida quedó accesible sin el middleware (RF-10).

## CHECKPOINTS.md

- **C1** — [x] Los 4 archivos base y los 4 docs existen; `./init.sh` exit code 0.
- **C2** — [x] Solo la feature 6 está `in_progress` en `feature_list.json` (confirmado
  programáticamente); toda feature `done` sigue con tests en verde;
  `progress/current.md` refleja la sesión activa, sin basura de sesiones anteriores.
- **C3** — [x] `src/` solo contiene módulos previstos en `docs/architecture.md`
  (`config`, `domain`, `auth`, `usuarios_client`, `broker`, `realtime`, `api`; `wiring`
  aún no implementado, consistente con el estado previo a esta feature); toda
  dependencia nueva de `Cargo.toml` (`tokio-executor-trait`, `tokio-reactor-trait`,
  `async-trait`, `uuid`, y en dev: `rustls`, `futures-util`) está justificada con
  comentario referenciando esta feature; sin `println!`/`dbg!` sueltos; sin
  `unwrap()`/`expect()`/`panic!()` fuera de `#[cfg(test)]` (verificado con `grep` y
  lectura manual, todas las ocurrencias caen dentro de `mod tests`); `cargo doc --no-deps`
  genera sin warnings (vía `init.sh`); el endpoint especulativo de `ms-usuarios`
  (`scan-targets`) está documentado como tal en vez de tratarse como contrato
  confirmado — no se inventó el shape de la dependencia pendiente.
- **C4** — [x] Hay test de integración para `broker` (vía `tests/scan_submission.rs`,
  camino feliz) contra RabbitMQ real vía `testcontainers`, topología copiada literal
  (diff sin diferencias); `cargo test` muestra > 0 tests, todos verdes; `cargo clippy
  --all-targets -- -D warnings` sin advertencias.
- **C5** — [x] Sin archivos sospechosos sin trackear (`progress/explore_*.md`,
  `progress/impl_scan_submission.md`, `rabbitmq/`, `tests/scan_submission.rs` son todos
  artefactos esperados de esta sesión); pendiente de que el leader mueva la bitácora a
  `progress/history.md` y marque la feature `done` tras este review (fuera del alcance
  del reviewer).

## Conclusión

Los 7 criterios de aceptación pasan. `./init.sh`, `cargo test` (con y sin `--ignored`),
`cargo clippy` y `cargo fmt --check` están en verde. No se encontró ninguna fuga de
`ssh_credentials_ref` ni de la credencial AMQPS en logs/errores/respuestas HTTP.
`src/broker.rs` no redeclara topología de producción. La ruta `POST /api/scans` está
correctamente protegida por el middleware de sesión. La decisión de los dos
identificadores está bien fundamentada, verificada contra el contrato real de
`user-service`, y documentada de forma que no compromete la feature futura
`scan_outcome_relay`.

**No hay cambios requeridos.**
