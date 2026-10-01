# Implementación — feature 20: scan_outcome_consumer_reconnect

## Archivos modificados

- `src/broker.rs`:
  - Nota de diseño del módulo (doc-comment de cabecera) reemplazada: ya no
    dice "`BrokerConsumer` sigue sin reconexión automática", ahora explica
    el nuevo comportamiento y por qué no hace falta `RwLock` (consumidor de
    tarea única vs. publicador con concurrencia real).
  - `BrokerConsumer` gana 2 campos nuevos: `amqps_url: SecretString`,
    `vhost: String`, `ca_pem: Option<String>` (mismos 3 que
    `BrokerPublisher`, poblados en `connect_with_tls_config` con el mismo
    patrón).
  - `BrokerConsumer::run` reescrito: desestructura `self` en variables
    locales mutables (`amqps_url`, `vhost`, `ca_pem`, `mut connection`,
    `mut channel`) y envuelve la lógica de consumo en un `loop`. Al fallar
    `basic_consume` o agotarse el `Stream` de entregas, llama al nuevo
    helper `reconnect_consumer` y, si reconecta, reemplaza
    `connection`/`channel` y continúa el loop; si se agotan los reintentos,
    retorna (terminal, igual que antes).
  - Nuevo helper privado `reconnect_consumer(amqps_url, vhost, ca_pem) ->
    Option<(Connection, Channel)>`: reutiliza `connect_channel` (función
    libre ya compartida con el publicador, sin duplicarla), con backoff
    exponencial simple.
  - Nuevas constantes `RECONNECT_MAX_ATTEMPTS` (5) y
    `RECONNECT_INITIAL_BACKOFF` (1s, duplicado tras cada intento fallido ->
    esperas de 1s/2s/4s/8s entre los 5 intentos; el 5.º intento, si también
    falla, ya no espera, se rinde de inmediato — corregido tras observación
    no bloqueante del reviewer: el valor "16s" que se alcanza a calcular
    nunca se usa, porque no hay una 6.ª espera).
  - `BrokerPublisher` **no se tocó** (solo comparte `connect_channel`, sin
    cambios).
- `docs/architecture.md`: nueva nota breve (no reemplaza ninguna existente,
  confirmado por grep antes de empezar que no había ninguna sobre
  reconexión del Broker) junto a la sección de notificación SSE, explicando
  que tanto publicador como consumidor reconectan solos y por qué el
  publicador usa `RwLock` y el consumidor no.
- `tests/scan_outcome_consumer_reconnect.rs` (nuevo): test de integración
  `#[ignore = "requiere Docker"]`.

## Decisiones de diseño

- **Sin `RwLock`/interior-mutability en `BrokerConsumer`**: `run(self, ...)`
  consume `self` por valor y corre en una única tarea (`tokio::spawn`,
  lanzada una sola vez en `crate::run`) — no hay llamadas concurrentes a
  este consumidor como sí las hay al publicador desde múltiples requests
  HTTP. Un `loop` con variables locales mutables (desestructuradas de
  `self`) alcanza; evita la complejidad del `RwLock`/double-checked locking
  del publicador, que ahí sí es necesaria por la concurrencia real.
- **Backoff: 5 intentos, esperas 1s/2s/4s/8s entre ellos** (~15s de espera
  acumulada en el peor caso; el 5.º intento, si también falla, ya no espera
  — se rinde de inmediato). `RECONNECT_MAX_ATTEMPTS = 5`,
  `RECONNECT_INITIAL_BACKOFF = Duration::from_secs(1)`, duplicado tras cada
  intento fallido. Criterio: suficiente para absorber una caída transitoria
  del Broker (p. ej. ECS reemplazando su task) sin loguear ruido excesivo, y
  acotado para no colgar indefinidamente si RabbitMQ está genuinamente caído
  por un rato largo — mismo espíritu que pide el criterio de aceptación 2,
  valores elegidos por criterio propio (el enunciado los sugiere como
  ejemplo, no los fija).
  - **Corrección post-revisión**: el reviewer notó (no bloqueante) que el
    doc-comment original describía "1s/2s/4s/8s/16s" (~31s), pero el código
    real nunca duplica una 5.ª vez porque el intento 5 no espera si falla —
    se corrigieron los doc-comments de `src/broker.rs` (cabecera del
    módulo, `RECONNECT_INITIAL_BACKOFF`, `BrokerConsumer::run`,
    `reconnect_consumer`) y este informe para describir el comportamiento
    real en vez de cambiar el código (opción más simple, sin impacto en
    `docs/architecture.md`, que no mencionaba el detalle numérico).
- **Cualquier fin de stream se trata como fallo de conexión**: confirmado
  (leyendo `broker.rs` completo antes de implementar) que este codebase no
  tiene ningún mecanismo de shutdown ordenado del consumidor, así que no
  hay forma de distinguir "cierre explícito" de "conexión caída" — ambos
  casos entran al mismo camino de reconexión.
- **Reutilización estricta de `connect_channel`**: el helper
  `reconnect_consumer` llama a la misma función libre que ya usan
  `BrokerConsumer::connect_with_tls_config` y `BrokerPublisher`, sin
  duplicar lógica de conexión.
- **Logging del error real**: mismo criterio que `log_broker_publish_errors`
  (feature 19) — `tracing::warn!`/`tracing::error!` usan `error = ?err`
  (Debug, encadena el `lapin::Error` real vía `#[source]`), nunca el
  `Display` de `BrokerError` (que sigue sin exponer la URL/credencial
  AMQPS).
- **Enlaces rustdoc a símbolos privados**: los doc-comments *públicos* que
  mencionaban `RECONNECT_MAX_ATTEMPTS`/`RECONNECT_INITIAL_BACKOFF`/
  `reconnect_consumer` (privados) se escribieron como texto con comillas
  simples en vez de enlaces `[`...`]`, para no generar warnings de
  `rustdoc::private_intra_doc_links` (detectado por `cargo doc --no-deps`,
  corregido antes de cerrar la sesión).

## Verificación de los 6 criterios de aceptación

1. **Reconecta en vez de terminar** — `BrokerConsumer::run` ahora es un
   `loop`; al fallar `basic_consume` o agotarse el `Stream`, llama a
   `reconnect_consumer` y retoma el consumo si tiene éxito. Verificado por
   lectura de código y por el test de integración nuevo (ver criterio 5).
2. **Reintentos acotados con backoff** — `RECONNECT_MAX_ATTEMPTS = 5`,
   backoff 1s/2s/4s/8s entre los 5 intentos (~15s acumulados en el peor
   caso; el 5.º intento, si también falla, no espera); agotados los
   intentos, loguea (`?err`) y retorna (terminal). Verificado por lectura
   de código; el test de
   integración ejerce el camino de éxito (reconexión rápida porque el
   contenedor sigue vivo), no el de agotamiento (no es práctico de
   reproducir de forma determinista contra un Broker real sin alargar el
   test innecesariamente).
3. **Sin cambio de contrato con conexión sana** — `cargo test` (sin
   `--ignored`) y `cargo test -- --ignored` muestran que
   `tests/scan_outcome_relay.rs` (feature 7, no tocado) sigue pasando sin
   modificaciones, igual que el resto de la suite (67 tests unitarios + 29
   de integración).
4. **Docs actualizadas** — `docs/architecture.md` (nueva nota, no reemplaza
   ninguna existente) y el doc-comment de `BrokerConsumer`/`BrokerConsumer::run`
   en `src/broker.rs` reflejan el nuevo comportamiento.
5. **Test de integración nuevo** — `tests/scan_outcome_consumer_reconnect.rs`,
   `#[ignore = "requiere Docker"]`, mismo patrón `testcontainers` que
   `scan_outcome_relay.rs`/`broker_publisher_reconnect.rs`: fuerza el cierre
   de la conexión AMQP del consumidor vía la Management HTTP API (reutiliza
   el mecanismo de `broker_publisher_reconnect.rs`), espera
   determinísticamente (polling de `/api/connections`, sin tiempos fijos ni
   republicación a ciegas) a que aparezca una conexión nueva, y confirma que
   un escaneo publicado después sigue relayándose por SSE — sin reiniciar el
   proceso de gateway (misma tarea `tokio::spawn` de principio a fin del
   test). Pasó en `cargo test -- --ignored` (15.4s) y en `./init.sh`.
6. **Comandos de verificación**:
   - `cargo build` → OK.
   - `cargo clippy --all-targets -- -D warnings` → OK, sin warnings.
   - `cargo fmt --check` → OK (tras un `cargo fmt` para el archivo de test
     nuevo).
   - `cargo test` (sin `--ignored`) → 67 tests unitarios + tests de
     integración no-Docker, todos verdes.
   - `cargo test -- --ignored` (con Docker disponible) → 5 tests de
     integración con `testcontainers`, todos verdes, incluido el nuevo.
   - `cargo doc --no-deps` → sin warnings (tras corregir los enlaces
     intra-doc rotos mencionados arriba).
   - `./init.sh` → `[OK] Entorno listo.`

## Dudas / bloqueos

Ninguno. No se tocó `BrokerPublisher` ni ningún otro módulo fuera del
scope de la feature 20. No se dejaron contenedores Docker huérfanos
(`testcontainers`/Ryuk los limpia automáticamente; verificado con
`docker ps -a --filter status=exited`).
