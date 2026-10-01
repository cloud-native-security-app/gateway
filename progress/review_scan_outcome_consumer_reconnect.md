# Review — feature 20 (scan_outcome_consumer_reconnect)

**Veredicto:** APPROVED

## Criterios de aceptación (feature_list.json id=20)

1. **`BrokerConsumer::run` reconecta en vez de terminar** — PASA.
   `src/broker.rs`: `run` desestructura `self` en variables locales
   (`amqps_url`, `vhost`, `ca_pem`, `mut connection`, `mut channel`) y
   envuelve la lógica original en un `loop`. Al fallar `basic_consume`
   (rama `Err(source) => ... reconnect_consumer(...)`) o al agotarse el
   `Stream` de `consumer.next()` (bloque tras el `while let`, llama de
   nuevo a `reconnect_consumer`), reemplaza `connection`/`channel` y
   continúa el `loop` en vez de retornar. Verificado por lectura de código
   y por `tests/scan_outcome_consumer_reconnect.rs` (ver criterio 5).

2. **Reintentos acotados con backoff creciente** — PASA, con una
   imprecisión menor en la documentación. `reconnect_consumer`
   (`src/broker.rs`, función nueva) itera `for attempt in
   1..=RECONNECT_MAX_ATTEMPTS` (`RECONNECT_MAX_ATTEMPTS = 5`); si el
   intento `attempt == RECONNECT_MAX_ATTEMPTS` falla, loguea con
   `tracing::error!(error = ?err, ...)` y retorna `None` (fin del loop
   externo, `return` en `run`) — NO es un bucle infinito, está acotado.
   El backoff dobla en cada intento fallido salvo el último (no se
   duerme tras el 5º intento porque ya no hay un 6º que reintentar).
   **Hallazgo concreto (no bloqueante):** el doc-comment nuevo
   (`src/broker.rs`, línea ~153-158, constante `RECONNECT_INITIAL_BACKOFF`)
   y `progress/impl_scan_outcome_consumer_reconnect.md` (líneas 47-54)
   afirman la secuencia "1s/2s/4s/8s/16s" y "~31s en el peor caso", pero
   trazando el código: con 5 intentos solo hay 4 esperas reales (antes de
   los intentos 2, 3, 4 y 5: 1s, 2s, 4s, 8s — el valor `backoff=16s` se
   calcula tras el 4º fallo pero nunca se usa, porque el 5º intento no
   duerme antes de rendirse). El peor caso real es ~15s, no ~31s. Esto no
   invalida el criterio (sigue habiendo backoff creciente y un límite
   duro), pero el doc-comment sobredimensiona la espera documentada en una
   entrada de más. Sugerido para una futura corrección menor: ajustar el
   comentario a "1s/2s/4s/8s (4 esperas para 5 intentos)" o cambiar el
   código para que también espere antes del intento final si se quiere
   preservar la narrativa de 5 esperas.

3. **Ningún cambio de contrato observable con la conexión sana** — PASA.
   `src/api.rs`, `src/auth.rs`, `src/wiring.rs`, `src/lib.rs` no fueron
   tocados (`git diff --stat` solo muestra `docs/architecture.md`,
   `feature_list.json`, `progress/current.md`, `src/broker.rs`). El test
   nuevo verifica explícitamente el camino sano (`SCAN_ID_BEFORE`) antes
   de forzar el corte, y toda la suite existente
   (`tests/scan_outcome_relay.rs`, `tests/scan_submission.rs`, etc.) sigue
   verde sin modificaciones.

4. **`docs/architecture.md` y el doc-comment de `BrokerConsumer`/`run` en
   `broker.rs` reflejan la reconexión** — PASA. `docs/architecture.md`
   agrega una nota nueva (no reemplaza ninguna existente, confirmado por
   `git diff`) junto a la sección de SSE/Broker, coherente con el resto
   del documento (no duplica ni contradice nada). El doc-comment de
   cabecera del módulo y el de `BrokerConsumer`/`BrokerConsumer::run`
   reemplazan explícitamente la nota vieja ("sigue sin reconexión
   automática" / "no reconecta... si la caída se considera inaceptable,
   reiniciar el proceso completo") por la descripción del comportamiento
   nuevo. Ver el hallazgo del criterio 2 sobre la precisión del backoff
   documentado (no bloqueante).

5. **Test de integración nuevo que fuerza el cierre y confirma relay
   posterior sin reiniciar el proceso** — PASA.
   `tests/scan_outcome_consumer_reconnect.rs` reutiliza literalmente el
   mecanismo de `tests/broker_publisher_reconnect.rs`
   (`force_close_gateway_connection` vía `DELETE
   /api/connections/{name}` de la Management HTTP API de
   `rabbitmq:4.3.5-management`, mismo usuario `lab-admin`), no reinventa
   nada. Añade `wait_for_gateway_reconnect` (polling determinista de
   `/api/connections` hasta ver una conexión *distinta* de la cerrada,
   timeout 30s) en vez de asumir un tiempo fijo. El test publica un evento
   `started` ANTES del corte (`SCAN_ID_BEFORE`, confirma el camino sano) y
   otro DESPUÉS (`SCAN_ID_AFTER`) sobre la misma tarea `tokio::spawn` de
   principio a fin — sin reiniciar el proceso de gateway. Ejecutado
   realmente contra Docker: pasó en `cargo test -- --ignored` (18.14s) y
   dentro de `./init.sh` (14.77s).

6. **Comandos de verificación en verde** — PASA, ejecutados yo mismo, no
   solo leídos del reporte:
   - `cargo build` → compiló sin warnings.
   - `cargo fmt --check` → sin diffs (exit 0).
   - `cargo clippy --all-targets -- -D warnings` → sin advertencias.
   - `cargo test` (sin `--ignored`) → todo verde, incluidas
     `tests/scan_outcome_relay.rs`, `tests/scan_submission.rs`, etc.
     (features 1-19 no se rompieron).
   - `cargo test -- --ignored` (con Docker disponible, confirmado
     `docker info`) → todo verde, incluido el test nuevo
     (`consumer_reconnects_and_relays_sse_events_of_a_later_scan_without_restarting_the_process`,
     18.14s) y `broker_publisher_reconnect` (12.72s) sin interferencia
     entre ambos.
   - `./init.sh` → `[OK] Entorno listo.` (exit 0), incluye `cargo doc
     --no-deps` sin warnings.

## Evaluación de la decisión de NO usar `RwLock`

Correcta. `BrokerConsumer::run(self, handler: Arc<dyn ScanOutcomeHandler>)`
consume `self` **por valor** y `crate::wiring`/`crate::lib::run` lo lanza
una única vez con `tokio::spawn` — no hay ninguna otra referencia a esa
instancia de `BrokerConsumer` compitiendo por la conexión/canal mientras
`run` vive. La reconexión se implementó desestructurando `self` en
variables locales mutables (`mut connection`, `mut channel`) reemplazadas
dentro del mismo `loop`, que es estrictamente de una sola tarea. Esto es
correcto a diferencia de `BrokerPublisher`, que sí necesita
`RwLock<PublisherConnection>` porque `publish_scan_request`/
`publish_scan_cancellation` se invocan concurrentemente desde múltiples
requests HTTP sobre la misma instancia compartida (`Arc<BrokerPublisher>`).
Agregar un `RwLock` en `BrokerConsumer` habría sido complejidad
injustificada (viola el principio de homogeneidad de
`docs/conventions.md` solo si se copia sin razón; aquí la razón de
diferir del patrón del publicador está explícitamente documentada y es
válida).

## Seguridad (`docs/security-scope.md`)

- `amqps_url: SecretString` nuevo en `BrokerConsumer` nunca se expone vía
  `Display`/`Debug` directo: el único lugar que lo desenvuelve
  (`.expose_secret()`) es `build_amqps_uri`/`connect_channel`, función
  libre ya existente y ya auditada en la feature `broker_publisher_reconnect`
  — no se agregó ningún nuevo call site que loguee la URL/credencial AMQPS.
- Los logs nuevos de `reconnect_consumer` (`tracing::warn!`/
  `tracing::error!`) usan `error = ?err` sobre el `lapin::Error` (nunca la
  URL ni la credencial), mismo criterio que `log_broker_publish_errors`
  (feature 19, ya `done`).
- Ninguna ruta HTTP ni el middleware de sesión (RF-10) fueron tocados —
  esta feature es exclusivamente interna a `src/broker.rs`.
- `BrokerPublisher` no fue modificado (solo referenciado en comentarios);
  comparten únicamente la función libre `connect_channel`, sin duplicar
  lógica de conexión.

## Cambios requeridos

Ninguno bloqueante. Se deja registrada la imprecisión del criterio 2
(doc-comment/`progress/impl_...md` describen una 5ª espera de 16s y un
peor caso de ~31s que el código no ejecuta; el peor caso real es ~15s con
4 esperas) como mejora menor opcional para una sesión futura, no impide
la aprobación de esta feature.
