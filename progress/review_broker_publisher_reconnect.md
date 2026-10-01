# Review — feature 18 broker_publisher_reconnect

**Veredicto:** APPROVED

## Verificación independiente ejecutada por el reviewer

- `cargo build` → OK.
- `cargo fmt --check` → exit 0, sin diferencias.
- `cargo clippy --all-targets -- -D warnings` → exit 0, sin warnings.
- `cargo test` (sin `--ignored`) → 65 unitarios + toda la suite de
  integración no-Docker en verde (features 1-17 intactas).
- `cargo test -- --ignored` (Docker real disponible) → todos los
  `#[ignore]` en verde, incluido
  `tests/broker_publisher_reconnect.rs::publisher_reconnects_and_a_later_publish_succeeds_without_restarting_the_process`.
- `./init.sh` → `[OK] Entorno listo.` (incluye `cargo doc --no-deps` sin
  warnings).

## Criterios de aceptación (feature_list.json id=18)

1. **PASA** — `src/broker.rs:291-321`: `PublisherConnection { connection,
   channel }` vive detrás de `conn: RwLock<PublisherConnection>` dentro de
   `BrokerPublisher`, junto con `amqps_url: SecretString`, `vhost: String`
   y `ca_pem: Option<String>` (extraído de `tls_config.cert_chain` en el
   momento de conectar). `connect`/`connect_with_tls_config` no cambiaron
   de firma pública: el llamante (`wiring.rs`) sigue pasando lo mismo de
   antes; es el struct quien ahora retiene lo necesario para reconectar
   sin pedírselo de nuevo. `ca_pem` en vez de guardar literalmente
   `OwnedTLSConfig` está justificado y verificado: `OwnedTLSConfig`
   (`tcp-stream` 0.28.0) no deriva `Clone`, y este repo nunca usa el campo
   `identity` (`None` siempre) — es un dato equivalente, no un atajo que
   pierda capacidad de reconectar.

2. **PASA** — `is_connection_error` (`src/broker.rs:433-438`) solo
   devuelve `true` para `BrokerError::PublishFailed`/`ConnectionFailed`,
   nunca para `NotAcknowledged`. Verificado en código (comentario explícito
   "el mensaje sí llegó, el Broker simplemente lo rechazó") y en 4 tests
   unitarios nuevos (`is_connection_error_is_true_for_publish_failed`,
   `..._true_for_connection_failed`, `..._false_for_not_acknowledged`,
   `..._false_for_serialization_failed`), todos verdes. `publish_and_confirm`
   (`src/broker.rs:455-478`) solo entra al camino de reconexión/reintento
   cuando `is_connection_error(&original_err)` es `true`; en cualquier otro
   caso (incluido un `nack` real) propaga el error del primer intento sin
   tocar la conexión.

3. **PASA** — `reconnect()` (`src/broker.rs:393-425`) hace
   double-checked locking: adquiere el write-lock y, antes de reconectar de
   verdad, vuelve a comprobar `guard.connection.status().connected()`; si
   otra tarea ya reconectó mientras esta esperaba el lock, retorna sin
   abrir una segunda conexión. El camino feliz (`try_publish_and_confirm`,
   línea 483-521) solo toma `read()`, así que publicaciones sanas
   concurrentes no se serializan entre sí — mecanismo correcto y suficiente
   sin `Mutex`/semáforo aparte, tal como permite `RwLock`. No hay test de
   concurrencia dedicado (el implementer lo documenta como limitación
   consciente), pero el mecanismo en sí es correcto por inspección y el
   test de integración (criterio 6) sí ejerce el camino real de
   reconexión+reintento end-to-end.

4. **PASA, con cambio sync→async evaluado y aceptado** — `is_connected()`
   de `BrokerPublisher` (`src/broker.rs:388`) pasa de `pub fn` a `pub async
   fn` porque ahora lee el estado a través de `self.conn.read().await`.
   Verificado con `rg "is_connected" .` en todo el repo (no solo `src/
   tests`, también `progress/`, `feature_list.json`): el único código de
   producción o de tests que invocaba `is_connected()` antes de esta
   feature era el propio `src/broker.rs` (comentario) y
   `progress/impl_scan_submission.md`, que documenta que el método
   solo existía para evitar `dead_code` en el campo `connection` — nunca
   tuvo un llamante real. `src/wiring.rs` no lo usa, `src/api.rs::health`
   tampoco. La firma de `BrokerConsumer::is_connected()` (línea 612, no
   tocada) se mantiene síncrona — son tipos distintos, no hay
   inconsistencia de API pública compartida. El cambio es razonable y
   necesario: `tokio::sync::RwLock` no ofrece lectura síncrona sin bloqueo
   salvo `try_read` (que no encaja: podría devolver un falso "no conectado"
   mientras hay una reconexión en vuelo), y no rompe ningún llamante
   existente, confirmado exhaustivamente.

5. **PASA** — El trait `ScanRequestPublisher` (`src/broker.rs:274-289`) no
   cambió: ambos métodos siguen `&self` (nunca `&mut self`), misma firma
   `async fn ... -> Result<(), BrokerError>`. `git diff HEAD -- src/wiring.rs`
   está vacío — ningún cambio en la composition root. El camino feliz
   (conexión sana, sin fallos) no se modificó: `try_publish_and_confirm`
   reproduce exactamente la lógica anterior de `basic_publish` + espera de
   confirmación, solo que ahora detrás de un `read()` del lock en vez de un
   acceso directo al campo.

6. **PASA** — `tests/broker_publisher_reconnect.rs` (nuevo, `#[ignore =
   "requiere Docker"]`), mismo patrón `testcontainers` que
   `scan_submission.rs`/`scan_outcome_relay.rs`. Usa la Management HTTP API
   de `rabbitmq:4.3.5-management` (`DELETE /api/connections/{name}`, con el
   usuario `lab-admin`) para cerrar de verdad la conexión AMQP subyacente
   del `BrokerPublisher` bajo prueba — sin reiniciar el proceso ni
   reconstruir el publicador. Espera (polling acotado) a que
   `is_connected()` refleje el corte antes de publicar de nuevo (evita
   depender de una condición de carrera favorable), y tras la publicación
   posterior verifica tanto `Ok(())` como el contenido real del mensaje
   consumido de una cola de verificación bindeada a
   `scan.requests`/`scan.request` — no se conforma con el resultado del
   método. Ejecutado contra Docker real por el reviewer: verde
   (`cargo test -- --ignored`, 9.4s).

7. **PASA** — Confirmado independientemente por el reviewer (no solo
   tomado del informe del implementer): `cargo fmt --check`, `cargo clippy
   --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored`
   e `./init.sh` todos en verde, ver sección de verificación arriba.

## Otros puntos revisados

- **`BrokerConsumer` no tocado de forma observable**: comparten
  `connect_channel` (sin cambios) con `BrokerPublisher`; `BrokerConsumer`
  mantiene campos directos (`connection`, `channel`), `is_connected()`
  síncrona, y `run()` sigue sin reconexión (documentado explícitamente en
  el comentario de módulo actualizado, que distingue el comportamiento de
  ambos). `git diff` confirma que las únicas líneas tocadas de
  `BrokerConsumer` son comentarios de la nota de diseño del módulo.
- **Sin `unwrap()`/`expect()`/`panic!()` nuevos fuera de tests**: verificado
  con grep acotado al código de producción de `src/broker.rs` (antes del
  `#[cfg(test)]`), sin resultados.
- **Credencial AMQPS nunca expuesta**: `amqps_url` se guarda como
  `SecretString` (no `String`) dentro de `BrokerPublisher`; ni
  `BrokerPublisher` ni `PublisherConnection` derivan `Debug`; no hay ningún
  `tracing::`/log nuevo que incluya `amqps_url`/`ca_pem`. `BrokerError`
  (sin cambios en sus variantes) sigue sin incluir la URL/credencial en su
  `Display`.
- **Capas/arquitectura**: `src/` solo contiene los módulos previstos en
  `docs/architecture.md` (sin módulos nuevos). El cambio vive enteramente
  en la capa `broker`, consistente con su responsabilidad documentada.
- **`feature_list.json`/`progress/current.md`**: la feature sigue
  correctamente en `in_progress` (el implementer no la marcó `done`,
  respeta el protocolo de que solo el leader cierra features).
- **`.atl/` sin trackear**: es un directorio de caché de tooling de sesión
  (`skill-registry.md`/`.skill-registry.cache.json`), ajeno a esta feature
  y no creado por el implementer para ella — no es un artefacto sospechoso
  de esta feature (no es `*.tmp` ni `target/`).

## Checkpoints relevantes a esta feature

- C1 (arnés completo, `./init.sh` verde): [x]
- C3 (arquitectura: capas, sin `unwrap`/`panic!` sin justificar, rustdoc
  completo vía `cargo doc --no-deps`, sin shape inventado de API
  pendiente): [x]
- C4 (verificación real: test de integración contra RabbitMQ real vía
  `testcontainers`, `cargo test` > 0 y verde, clippy sin warnings): [x]

## Cambios requeridos

Ninguno.
