# Implementación — feature 18 `broker_publisher_reconnect`

## Archivos modificados/creados

- `src/broker.rs` (modificado): `BrokerPublisher` pasa de campos directos
  (`connection: Connection, channel: Channel`) a interior-mutability
  (`tokio::sync::RwLock<PublisherConnection>`), más `amqps_url`/`vhost`/
  `ca_pem` guardados para poder reconectar. Lógica de reconexión y reintento
  en `publish_and_confirm`. Nota de diseño del módulo actualizada
  (sustituye la sección "Sin reconexión automática" por una que distingue
  el comportamiento del publicador — ahora con reconexión — del
  consumidor — sigue sin ella, sin tocar `BrokerConsumer`). Tests unitarios
  nuevos para `is_connection_error`.
- `tests/broker_publisher_reconnect.rs` (nuevo): test de integración
  `#[ignore = "requiere Docker"]` que reproduce el incidente real.

No se tocó `BrokerConsumer` (se confirmó que `connect_channel` es la única
función compartida entre publicador y consumidor, y no se le cambió el
comportamiento).

## Decisiones de diseño

### Mecanismo de lock

`BrokerPublisher::conn: RwLock<PublisherConnection>` (struct interna que
agrupa `connection`/`channel` para reemplazarlos atómicamente). El camino
feliz (`try_publish_and_confirm`) solo toma un **read-lock** — publicaciones
concurrentes sanas no se serializan entre sí. `reconnect()` escala a
**write-lock** únicamente cuando `publish_and_confirm` detectó un error de
conexión, y hace *double-checked locking*: una vez con el write-lock,
vuelve a comprobar `connection.status().connected()` antes de reconectar de
verdad — si otra tarea concurrente ya reconectó mientras esta esperaba el
lock, no abre una segunda conexión real. Esto cubre el criterio 3 sin
`Mutex`/semáforo aparte, tal como permite la sincronización del propio
`RwLock`.

`publish_and_confirm`: en el primer fallo, solo dispara reconexión si
`is_connection_error(&err)` es `true` (`PublishFailed`/`ConnectionFailed`,
nunca `NotAcknowledged` — un nack real no es problema de conexión). Si
`reconnect()` falla, o si el reintento de publicación tras reconectar
también falla, se propaga el error **original** del primer intento (no el
de la reconexión ni el del reintento) — así lo pide literalmente el
criterio 2 ("propaga el error original si vuelve a fallar").

`is_connected()` pasó de síncrona a `async fn` porque ahora lee el estado a
través del `RwLock` (tokio no ofrece lectura síncrona sin bloquear salvo
`try_read`, que no encaja aquí). Se verificó por `rg` que ningún código de
producción ni de tests llamaba a `is_connected()` todavía, así que no rompe
ningún contrato existente — documentado explícitamente en el rustdoc del
método.

### `OwnedTLSConfig` no es `Clone`

Se confirmó en el código fuente real de `tcp-stream` 0.28.0 (dependencia
transitiva de `lapin` 2.5.5 vía `amq-protocol-tcp`):
`#[derive(Default, Debug, PartialEq)] pub struct OwnedTLSConfig { identity:
Option<OwnedIdentity>, cert_chain: Option<String> }` — sin `Clone`, y
`OwnedIdentity` tampoco lo deriva. Como este repo nunca usa el campo
`identity` (siempre `None`), se guarda únicamente `ca_pem: Option<String>`
(extraído de `tls_config.cert_chain.clone()` en el momento de conectar) y se
reconstruye un `OwnedTLSConfig { identity: None, cert_chain: self.ca_pem
.clone() }` nuevo en cada reconexión — más simple que intentar clonar el
tipo de `lapin`.

### Test de integración (criterio 6)

Nuevo archivo (no se tocó `scan_submission.rs`/`scan_outcome_relay.rs`,
solo se siguió su mismo patrón): levanta `rabbitmq:4.3.5-management` vía
`testcontainers` con la topología de `broker/rabbitmq/definitions.json` y
TLS de `broker/rabbitmq/tls/` (copiados literalmente, sin re-derivar).
Conecta un `BrokerPublisher` real como el usuario `gateway`. Para forzar el
cierre de la conexión AMQP subyacente se usó la **Management HTTP API**
(puerto 15672, ya expuesto en la imagen `-management`) con el usuario
`lab-admin` (`administrator`, `broker/rabbitmq/definitions.json`):

1. `GET /api/connections` (con polling acotado a 15s, porque el plugin de
   management recolecta sus estadísticas de forma periódica, no
   instantánea al conectar) hasta encontrar la conexión del usuario
   `gateway`.
2. `DELETE /api/connections/{name}` (nombre construido con
   `url::Url::path_segments_mut().push(...)` para el percent-encoding
   correcto del nombre de conexión, que trae espacios y `->`).

Se eligió esto en vez de reiniciar el contenedor entero porque es más
rápido y determinista (no hay que esperar a que el contenedor completo
vuelva a levantar con Docker). El test espera (polling acotado, 10s) a que
`publisher.is_connected().await` refleje el corte antes de publicar de
nuevo, para ejercer de verdad el camino de reconexión en vez de depender de
una condición de carrera favorable. Tras la publicación posterior, además
de comprobar que `publish_scan_request` devuelve `Ok`, se verifica el
contenido real del mensaje consumido de una cola de verificación bindeada a
`scan.requests`/`scan.request` (mismo patrón que el test de camino feliz de
`scan_submission.rs`) — nunca solo el status/resultado del método.

Gotcha encontrado y corregido durante la verificación: la URL base para el
`DELETE` no debía llevar `/` final antes de `path_segments_mut().push(...)`
— con `/` final, `url` genera un segmento vacío adicional
(`/api/connections//<name>`) que la Management API responde con `405
Method Not Allowed` en vez de `204`.

## Verificación de los 7 criterios de aceptación

1. **RwLock + datos para reconectar sin pedirlos de nuevo**: confirmado en
   `src/broker.rs` — `BrokerPublisher { amqps_url, vhost, ca_pem, conn:
   RwLock<PublisherConnection> }`; `connect`/`connect_with_ca_pem` no
   cambiaron de firma pública.
2. **Reconexión única + reintento único, nunca por `NotAcknowledged`**:
   `publish_and_confirm` + `is_connection_error` + tests unitarios
   `is_connection_error_is_{true,false}_for_*` (4 tests) que fijan
   explícitamente que `NotAcknowledged`/`SerializationFailed` no disparan
   reconexión y que `PublishFailed`/`ConnectionFailed` sí.
3. **Reconexiones concurrentes no duplican conexión**: double-checked
   locking bajo el write-lock en `reconnect()` (documentado en su rustdoc).
   No se escribió un test de concurrencia dedicado (difícil de hacer
   determinista sin instrumentar el conteo de conexiones reales desde
   dentro del test); se verificó por inspección de código y quedó
   documentado como la garantía que ofrece el propio `RwLock`.
4. **`is_connected()` sigue reflejando el estado vigente a través del
   lock**: confirmado, ahora `async`, documentado por qué (sin romper
   ningún llamante existente, verificado con `rg "is_connected"
   src tests` antes del cambio).
5. **Sin cambio de contrato en `ScanRequestPublisher` ni en el camino
   feliz**: la firma del trait no cambió; toda la suite de tests
   preexistente (65 unitarios + toda `tests/`, incluidos los
   `#[ignore]`) sigue en verde sin modificarse ningún test existente.
6. **Test de integración nuevo**: `tests/broker_publisher_reconnect.rs::
   publisher_reconnects_and_a_later_publish_succeeds_without_restarting_the_process`,
   ejecutado contra Docker real, en verde.
7. **Comandos de verificación**, todos ejecutados y en verde:
   - `cargo build` → OK.
   - `cargo fmt --check` → OK (exit 0).
   - `cargo clippy --all-targets -- -D warnings` → OK, sin warnings.
   - `cargo test` (sin `--ignored`) → 65 unitarios + toda la suite de
     integración no-Docker en verde (nada de las features 1-17 se rompió).
   - `cargo test -- --ignored` (con Docker disponible) → todos los tests
     marcados `#[ignore]` en verde, incluido el nuevo.
   - `./init.sh` → `[OK] Entorno listo.` (incluye `cargo doc --no-deps` sin
     warnings; se corrigió un warning de rustdoc por un link a un ítem
     privado detectado en esta misma verificación).

## Dudas / bloqueos

Ninguno. No se tocó `docs/security-scope.md` porque este fix no cambia
ningún límite de seguridad ya documentado (sigue siendo AMQPS siempre,
credencial nunca loggeada — la credencial se guarda en el mismo tipo
`SecretString` que ya se usaba, solo que ahora también vive clonada dentro
de `BrokerPublisher` para poder reconectar, nunca en un log ni en un
mensaje de error).
