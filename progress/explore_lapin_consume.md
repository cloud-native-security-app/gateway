# Explore: `lapin` consume (AMQPS) para `gateway` — feature `scan_outcome_relay`

> Investigación de solo-lectura (no toca `Cargo.toml`/`src/`/`tests/`). Cubre
> únicamente **consumir** la cola `gateway.scan-outcomes` (`basic_consume` +
> `ack`/`nack`), no publicar — eso ya lo implementó la feature `scan_submission`
> (`src/broker.rs`, `BrokerPublisher`) y lo documenta
> `progress/explore_lapin_publish.md`, que se **reutiliza sin reinvestigar**
> para todo lo relativo a conexión AMQPS (§0 de este documento).

## 0. Versión y reutilización de la conexión ya investigada

`gateway/Cargo.lock` confirma **`lapin 2.5.5`** (mismo comando que usó la
investigación anterior: `grep -A3 'name = "lapin"' Cargo.lock`), no `4.x`
como el repo hermano `broker`. Todo lo que sigue está verificado contra el
código fuente real local de esa versión exacta:
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/lapin-2.5.5/`
(`src/channel.rs`, `src/consumer.rs`, `src/message.rs`, `src/acker.rs`,
`src/generated.rs`, `src/connection.rs`, `examples/reconnect.rs`).

**No se reinvestiga la conexión AMQPS.** `progress/explore_lapin_publish.md`
(feature `scan_submission`) ya estableció, y sigue vigente sin cambios para
consumir:

- `Connection::connect_with_config(uri, ConnectionProperties, OwnedTLSConfig)`,
  con `uri` = `amqps://.../<vhost>` construido igual que
  `BrokerPublisher::build_amqps_uri` (`src/broker.rs` líneas 264-270).
- `ConnectionProperties::default().with_executor(tokio_executor_trait::Tokio::current()).with_reactor(tokio_reactor_trait::Tokio)`
  — ya son dependencias declaradas en `Cargo.toml` (`tokio-executor-trait`,
  `tokio-reactor-trait`), no hace falta añadir nada para el consumidor.
- `lapin` 2.5.5 **no reconecta solo** (confirmado de nuevo en
  `src/connection.rs`/`examples/reconnect.rs` — sin cambios respecto a lo ya
  documentado). Ver §2 para cómo aplica esto al consumidor.
- `gateway.Cargo.toml` ya tiene `futures-util = "0.3"` (resuelto a `0.3.34`
  en `Cargo.lock`), pero **hoy solo como `[dev-dependencies]`** (comentario
  explícito: "`.next()` sobre el `Consumer`... en el test de integración de
  `scan_submission`"). Para que el consumidor de producción (`src/`, no
  `tests/`) llame `.next()` sobre el `Consumer`, `futures-util` debe pasar a
  `[dependencies]` (o añadir una entrada nueva ahí) — un cambio de
  `Cargo.toml`, no de `src/`/`tests/`, igual que ya se documentó para
  `tokio-executor-trait`/`tokio-reactor-trait` en la investigación anterior.

Para AMQPS con CA pública (caso normal de `gateway`, sin CA de laboratorio),
basta `BrokerPublisher::connect`/`connect_with_tls_config` como ya existen;
un `BrokerConsumer` análogo puede reutilizar el mismo `Connection` (una
`Connection` admite múltiples `Channel`, ver `src/broker.rs` que ya crea un
`Channel` sobre una `Connection`) o abrir su propia `Connection` — decisión
de diseño para el implementer, no algo que fije este documento.

---

## 1. API exacta de `lapin` 2.5.5 para consumir

### 1.1 Abrir el consumer — `Channel::basic_consume`

Firma real, `lapin-2.5.5/src/channel.rs` línea 304:

```rust
pub async fn basic_consume(
    &self,
    queue: &str,
    consumer_tag: &str,
    options: BasicConsumeOptions,
    arguments: FieldTable,
) -> Result<Consumer>
```

`BasicConsumeOptions` (`src/generated.rs`, struct generada, `Copy + Clone +
Default`):

```rust
pub struct BasicConsumeOptions {
    pub no_local: bool,   // default false
    pub no_ack: bool,     // default false — IMPORTANTE: false = ack/nack explícito
    pub exclusive: bool,  // default false
    pub nowait: bool,     // default false
}
```

Para `scan_outcome_relay`: `BasicConsumeOptions::default()` es lo correcto
— `no_ack: false` (el default) es justamente lo que exige el criterio de
aceptación ("un mensaje malformado... se descarta con un log... no tumba el
consumidor", lo cual requiere poder decidir `ack`/`nack` por mensaje; con
`no_ack: true` el servidor confirma automáticamente al entregar y no hay
forma de rechazar nada).

```rust
use lapin::{options::BasicConsumeOptions, types::FieldTable};

let consumer = channel
    .basic_consume(
        "gateway.scan-outcomes",
        "gateway-scan-outcome-relay", // consumer_tag: cualquier string estable/descriptivo
        BasicConsumeOptions::default(),
        FieldTable::default(),
    )
    .await
    .map_err(BrokerError::ConnectionFailed)?; // o una variante nueva análoga
```

### 1.2 Iterar — `Consumer` implementa `Stream<Item = Result<Delivery>>`

Confirmado en `src/consumer.rs` línea 412:

```rust
impl Stream for Consumer {
    type Item = Result<Delivery>; // lapin::Result<Delivery> = Result<Delivery, lapin::Error>
    fn poll_next(...) -> Poll<Option<Self::Item>> { ... }
}
```

`futures_util::StreamExt::next()` funciona sobre cualquier `Stream`
(`futures_util` reexporta el mismo trait `futures_core::Stream` que usa
`lapin` — no hace falta `futures_lite`, que es lo que usan los ejemplos
propios de `lapin` solo porque su demo usa `async-global-executor`; el
`Cargo.toml` de `gateway` ya trae `futures-util`, no `futures-lite`, así que
es la crate correcta a usar aquí, coherente con el test existente de
`scan_submission`). Nota: a diferencia del tipo público `DeliveryResult`
(`Result<Option<Delivery>>`, usado por el delegate `ConsumerDelegate`), el
`Stream` en sí ya "aplana" el `None` interno en el fin del stream — cada
`Some(item)` que produce el `Stream` es `Result<Delivery, lapin::Error>`
directamente (`src/consumer.rs` línea 413), no `Result<Option<Delivery>>`.

```rust
use futures_util::StreamExt;

while let Some(delivery) = consumer.next().await {
    match delivery {
        Ok(delivery) => { /* procesar, ver §3 */ }
        Err(err) => {
            // Error de transporte/protocolo (canal caído, etc.) — no un
            // problema de payload. Loggear y, según §2, terminar la task
            // (no hay delivery/Acker sobre el que hacer nack).
            tracing::error!(error = %err, "error consumiendo gateway.scan-outcomes");
        }
    }
}
// El bucle termina solo si el stream se agota (p. ej. tras basic_cancel o
// canal/conexión cerrados) — ver §2.
```

### 1.3 `ack`/`nack`/`reject` — vía `Delivery::acker` (`Acker`)

`Delivery` (`src/message.rs`) tiene un campo público `acker: Acker` y
además `impl Deref<Target = Acker> for Delivery` — por eso se puede llamar
`delivery.ack(...)`/`delivery.nack(...)` directamente sobre el `Delivery`,
sin desreferenciar a mano.

`Acker` (`src/acker.rs`) expone (todas `async fn ... -> lapin::Result<()>`):

```rust
pub async fn ack(&self, options: BasicAckOptions) -> Result<()>;
pub async fn nack(&self, options: BasicNackOptions) -> Result<()>;
pub async fn reject(&self, options: BasicRejectOptions) -> Result<()>;
```

Opciones (`src/generated.rs`, todas `Copy + Clone + Default`):

```rust
pub struct BasicAckOptions    { pub multiple: bool }              // default false
pub struct BasicNackOptions   { pub multiple: bool, pub requeue: bool } // default false, false
pub struct BasicRejectOptions { pub requeue: bool }                // default false
```

Uso concreto:

```rust
use lapin::options::{BasicAckOptions, BasicNackOptions};

// Mensaje procesado con éxito:
delivery.ack(BasicAckOptions::default()).await?;

// Mensaje malformado (ver §3) — SIN reintentar, directo al DLX ya
// configurado en la cola:
delivery.nack(BasicNackOptions { multiple: false, requeue: false }).await?;
```

Nota (`Acker::rpc`, `src/acker.rs`): un `Acker` solo se puede usar **una
vez** — la segunda llamada a `ack`/`nack`/`reject` sobre el mismo `Delivery`
devuelve `Err(Error::ProtocolError(PRECONDITIONFAILED))` ("Attempted to use
an already used Acker"). El código del consumidor debe decidir de una sola
vez qué hacer con cada `Delivery` (nunca `ack` y luego `nack`, ni al revés).

---

## 2. Correr el consumer como tarea de fondo — patrón y alcance de reconexión

### 2.1 `tokio::spawn`, sin bloquear el servidor axum

`gateway::run()` (`src/lib.rs`) hoy es un stub (`tracing::info!("starting")`)
— el bootstrap real de `axum::serve` todavía no está implementado en este
repo (ninguna otra feature lo hizo aún; confirmado: no hay
`axum::serve`/`TcpListener` en `src/api.rs` ni `src/realtime.rs`). Esto no
cambia el patrón recomendado, solo dónde se conecta: cuando se implemente el
bootstrap del servidor, el consumidor se lanza con `tokio::spawn` **antes**
de (o junto a) `axum::serve(...).await`, nunca `.await`eado en línea:

```rust
// dentro de gateway::run(), o de la función que arma el bootstrap final:
let consumer_handle = tokio::spawn(run_scan_outcome_relay(broker_consumer, /* lo que haga falta para reflejar el avance, p. ej. un sender hacia realtime.rs */));

// ... construir el router de axum con el AppState ya listo ...
axum::serve(listener, app).await.expect("servidor HTTP");
```

`tokio::spawn` es correcto porque el proceso ya corre bajo `#[tokio::main]`
(`src/main.rs`) — la tarea corre en el mismo runtime multi-hilo
(`tokio = { features = ["rt-multi-thread", ...] }`, `Cargo.toml`), sin
bloquear el loop de `axum::serve` en el hilo/tarea principal: son dos tasks
tokio independientes compartiendo el mismo runtime, exactamente el propósito
de `tokio::spawn`.

### 2.2 Reconexión — decisión de diseño explícita, sin sobre-ingeniería

Igual que confirmó `progress/explore_lapin_publish.md` §3.3 para el
publisher, `lapin` 2.5.5 **no reconecta solo** (nada ha cambiado al mirar el
lado consumidor: `Connection`/`Channel`/`Consumer` no tienen ningún método
de retry automático; `examples/reconnect.rs` de la propia crate confirma que
la reconexión es responsabilidad de la aplicación, ver el fragmento citado
en ese documento).

**Recomendación concreta para el alcance de `scan_outcome_relay` (evitar
sobre-ingeniería, criterio explícito de esta tarea):**

- La tarea de fondo (`tokio::spawn`) **no implementa retry/backoff
  automático de reconexión.** Si la `Connection`/`Channel` AMQPS se cae (el
  `while let Some(delivery) = consumer.next().await` termina, o cada
  operación empieza a devolver `Err`), la tarea **loggea el error con
  `tracing::error!` y termina** (`return`/sale del bucle, el `JoinHandle`
  se resuelve). No se reintenta conectar desde dentro de esa misma task.
- Esto es una decisión de diseño a documentar explícitamente en el código
  (comentario, igual que ya hace `src/broker.rs` para el publisher, líneas
  32-37): el relay de avance en tiempo real (RF-07/RF-08) es una capa de
  UX (progreso en vivo por SSE), no la vía de registro autoritativo del
  resultado de un escaneo — si se cae, el histórico ya se corrige por otros
  medios (`ms-analisis` sigue consumiendo `ms-analisis.scan-outcomes` de
  forma independiente). Construir aquí un supervisor con backoff
  exponencial, límite de reintentos, jitter, etc. sería sobre-ingeniería
  para lo que pide esta feature; si en producción se decide que la caída
  del relay es inaceptable, la mejora natural es que el **proceso completo**
  se reinicie (vía el orquestador/`systemd`/Kubernetes) al detectar que la
  task murió — no que `gateway` reimplemente su propio supervisor de
  reconexión AMQP.
- Si el `implementer` de esta feature quiere una señal explícita de que la
  task murió (para logs/alertas), puede loggear también el `JoinHandle`
  resuelto (`consumer_handle.await`) desde algún punto de observabilidad,
  pero **no** es un requisito de esta investigación resolver ese detalle.

---

## 3. Mensaje malformado: `ack` vs `nack(requeue=false)` — recomendación concreta

**Recomendación: `nack` (o `reject`, equivalentes aquí) con `requeue:
false` — NO `ack`.**

### 3.1 Por qué no `ack`

`ack` confirma al broker que el mensaje se puede **descartar
definitivamente**, sin dejar ningún rastro. Si `gateway` hiciera `ack` sobre
un mensaje que no decodifica contra `broker/contracts/scan-outcome.schema.json`
(p. ej. `ms-nmap` cambia el shape de `ScanOutcome` sin coordinarlo, o llega
basura), el mensaje desaparecería sin que nadie pueda inspeccionarlo
después — ni en la cola de trabajo ni en ninguna `.dlq`. Eso contradice que
la topología real (`broker/rabbitmq/definitions.json`, confirmado arriba en
§4) **ya aprovisionó** `gateway.scan-outcomes.dlq` específicamente para este
caso — usar `ack` en vez de aprovechar esa cola tira a la basura la
observabilidad que la topología ya ofrece sin coste adicional.

### 3.2 Por qué `nack(requeue=false)` y no `nack(requeue=true)`

Un mensaje que no decodifica contra el schema es un **fallo permanente**, no
transitorio: reintentarlo (requeue=true) nunca lo va a arreglar — el
`payload` no cambia entre reintentos. `requeue: true` solo tiene sentido
para fallos transitorios (p. ej. una dependencia externa caída
momentáneamente), que no es el caso de un error de deserialización.

Esto también es coherente con la propia experiencia empírica que dejó
documentada `broker/tests/retry_delivery_limit.rs` (líneas 10-22, nota
contra RabbitMQ 4.3.5 real): el contador que RabbitMQ compara contra
`x-delivery-limit=3` (ya configurado en `gateway.scan-outcomes`, ver §4)
**solo se incrementa con `basic.reject`**, no con `basic.nack(requeue=true)`
— es decir, si `gateway` intentara "reintentar" un mensaje malformado con
`nack(requeue=true)` esperando que el mecanismo de `x-delivery-limit` lo
sacara eventualmente de la cola, ese mecanismo **no se dispararía** contra
este broker real (según esa nota empírica) y el mensaje malformado
quedaría reintentándose indefinidamente en `gateway.scan-outcomes` — el
escenario exacto que el criterio de aceptación prohíbe ("sin dejarlo
reintentando infinitamente").

`requeue: false` evita todo ese problema por construcción: **no pasa por el
ciclo de `x-delivery-limit` en absoluto.** Un `nack`/`reject` con
`requeue: false` dead-lettera el mensaje **inmediatamente** (motivo
`rejected` en `x-death`, no `delivery_limit`) hacia el
`x-dead-letter-exchange`/`x-dead-letter-routing-key` ya declarados en
`gateway.scan-outcomes` (`scan.outcomes.dlx` /
`gateway.scan-outcomes.dead`, ver §4) — comportamiento estándar de AMQP
0-9-1 con DLX, documentado también por
`broker/progress/explore_retry_pattern.md` §1-2 (el "patrón clásico": un
`nack(requeue=false)` dead-lettera hacia el exchange configurado, motivo
`rejected`), y no depende de si la cola es `quorum` ni de ningún contador
de reintentos.

### 3.3 `nack` vs `reject` — cuál usar

Ambos logran lo mismo para un solo mensaje (`nack(requeue=false)` ≡
`reject(requeue=false)`, con `multiple: false` en el caso de `nack`, que es
el único caso relevante para descartar mensajes uno a uno). `nack` es la
opción algo más idiomática/flexible en `lapin` (permite `multiple`, aunque
no se necesite aquí) y ya es la que usa el propio ejemplo
`examples/reconnect.rs` de `lapin`, así que se recomienda `nack` por
consistencia, sin que sea una diferencia funcional relevante para este caso.

### 3.4 Qué loggear (criterio: "sin credenciales")

El log debe incluir información suficiente para diagnosticar (motivo del
fallo de deserialización, quizás el `routing_key`/`correlation_id` **si el
JSON parseó lo bastante como para extraerlo antes de fallar la validación
completa del schema**) pero **nunca el payload crudo completo** sin
redactar, porque `ScanOutcome.completed` puede contener hallazgos de
vulnerabilidades/escaneo (`ScanResult`) — no son credenciales per se (a
diferencia de `ssh_credentials_ref` en `ScanRequest`, que sí lo es y que
`src/broker.rs` ya redacta en su `Debug` manual), pero sigue siendo
información sensible de la plataforma que no debería aparecer sin criterio
en logs de texto plano. Recomendación: loggear el error de deserialización
de `serde_json`/`serde`-schema (mensaje de error, no el valor), el
`delivery.routing_key`, y opcionalmente el tamaño en bytes del payload —
no el `delivery.data` completo.

---

## 4. Confirmado: NO hace falta declarar la cola ni el binding

Dos fuentes independientes lo confirman:

1. **La topología ya existe real en `broker/rabbitmq/definitions.json`**
   (leído directamente en esta investigación): la cola `gateway.scan-outcomes`
   ya está declarada —

   ```json
   {
     "name": "gateway.scan-outcomes",
     "vhost": "security-app",
     "durable": true,
     "auto_delete": false,
     "arguments": {
       "x-queue-type": "quorum",
       "x-delivery-limit": 3,
       "x-dead-letter-exchange": "scan.outcomes.dlx",
       "x-dead-letter-routing-key": "gateway.scan-outcomes.dead"
     }
   }
   ```

   — y su binding también:

   ```json
   {
     "source": "scan.outcomes",
     "destination": "gateway.scan-outcomes",
     "destination_type": "queue",
     "routing_key": "scan.outcome.#"
   }
   ```

   (`scan.outcomes` es exchange `topic`, así que `scan.outcome.#` cubre las
   tres routing keys `scan.outcome.started`/`completed`/`failed` — coincide
   con lo que dice `broker/docs/architecture.md`: "el Gateway consume las
   tres"). También ya existen `gateway.scan-outcomes.dlq` y su binding desde
   `scan.outcomes.dlx` con routing key `gateway.scan-outcomes.dead` — el
   destino de los `nack(requeue=false)` de §3 ya está listo sin que
   `gateway` declare nada.

2. **Los permisos del usuario RabbitMQ `gateway` lo impiden a nivel de
   protocolo, no solo por convención** — confirmado leyendo la sección
   `permissions` de `broker/rabbitmq/definitions.json`:

   ```json
   {
     "user": "gateway",
     "vhost": "security-app",
     "configure": "^$",
     "write": "^scan\\.(requests|cancellations)$",
     "read": "^gateway\\.scan-outcomes$"
   }
   ```

   `configure: "^$"` es una regex que **no coincide con ningún nombre**
   (cadena vacía únicamente) — es decir, el usuario `gateway` no tiene
   permiso `configure` sobre **ninguna** entidad del vhost. Cualquier
   `queue_declare`/`exchange_declare`/`queue_bind` que este repo intentara
   ejecutar fallaría con `ACCESS_REFUSED` del lado de RabbitMQ,
   independientemente de que el código compile. `read` está además acotado
   con precisión quirúrgica a `^gateway\.scan-outcomes$` — ni siquiera puede
   leer otra cola por error de nombre.

**Conclusión: el código de `gateway` para esta feature debe limitarse a
`channel.basic_consume("gateway.scan-outcomes", ...)` directamente (§1.1),
sin ningún `queue_declare`/`queue_bind`/`exchange_declare` antes.** Esto es
consistente con el mismo principio que ya aplicó `scan_submission` para
publicar (`progress/explore_lapin_publish.md` §6: "no hace falta declarar
el exchange antes de publicar") — aquí el argumento es incluso más fuerte
porque, a diferencia de publicar (donde declarar mal solo cerraría el canal
al primer publish), aquí los permisos lo bloquean de raíz.

---

## 5. Fuentes citadas

- `lapin` 2.5.5 (versión real resuelta por `gateway/Cargo.lock`, confirmada
  con `grep -A3 'name = "lapin"' Cargo.lock`) — código fuente local:
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/lapin-2.5.5/`
  — `src/channel.rs` (`basic_consume`), `src/consumer.rs` (`Consumer`,
  `impl Stream`), `src/message.rs` (`Delivery`, `DeliveryResult`),
  `src/acker.rs` (`Acker::ack`/`nack`/`reject`), `src/generated.rs`
  (`BasicConsumeOptions`, `BasicAckOptions`, `BasicNackOptions`,
  `BasicRejectOptions`), `src/connection.rs` (`on_error`, sin reconexión
  automática), `examples/reconnect.rs` (patrón de reconexión manual, no
  aplicado aquí por decisión de alcance — ver §2.2).
- `gateway/progress/explore_lapin_publish.md` — reutilizado íntegramente
  para conexión AMQPS/TLS/executor-reactor (§0 de este documento); no
  reinvestigado.
- `gateway/Cargo.toml`/`Cargo.lock` — confirmación de `lapin 2.5.5`,
  `futures-util 0.3.34` (hoy solo `[dev-dependencies]`),
  `tokio-executor-trait`/`tokio-reactor-trait` ya presentes.
- `gateway/src/broker.rs` — `BrokerPublisher` existente (feature
  `scan_submission`): patrón de conexión, manejo de `BrokerError` con
  `thiserror`, convención de redactar campos sensibles en `Debug`.
- `gateway/src/lib.rs`, `src/main.rs` — confirmación de que `run()` es hoy
  un stub sin `axum::serve` todavía wireado (relevante para §2.1: el punto
  exacto de `tokio::spawn` lo fija quien implemente el bootstrap, no esta
  investigación).
- `broker/rabbitmq/definitions.json` (repo hermano, solo lectura) — cola
  `gateway.scan-outcomes` (con `x-queue-type: quorum`, `x-delivery-limit: 3`,
  `x-dead-letter-exchange: scan.outcomes.dlx`,
  `x-dead-letter-routing-key: gateway.scan-outcomes.dead`), su binding desde
  `scan.outcomes` (`scan.outcome.#`), `gateway.scan-outcomes.dlq` y su
  binding desde `scan.outcomes.dlx`, y los permisos del usuario `gateway`
  (`configure: "^$"`, `read: "^gateway\.scan-outcomes$"`).
- `broker/contracts/scan-outcome.schema.json` (repo hermano, solo lectura)
  — las tres variantes `started`/`completed`/`failed` con discriminador
  `status`, usadas en §3 para razonar sobre "qué es un mensaje malformado".
- `broker/progress/explore_retry_pattern.md` (repo hermano, solo lectura)
  — decisión de `x-delivery-limit=3` sobre colas quorum, estructura del
  header `x-death`, y el patrón clásico de DLX con `requeue=false` (§1-2),
  citado en §3.2 para justificar por qué `nack(requeue=false)` dead-lettera
  de inmediato sin pasar por el contador de reintentos.
- `broker/tests/retry_delivery_limit.rs` (repo hermano, solo lectura) —
  nota empírica (líneas 10-22) de que `x-delivery-limit` contra RabbitMQ
  4.3.5 real solo cuenta `basic.reject`, no `basic.nack(requeue=true)`;
  usada en §3.2 para descartar `requeue: true` como opción para mensajes
  malformados.
- `broker/tests/outcome_routing.rs` (repo hermano, solo lectura) — confirma
  por test real que `scan.outcome.started`/`completed` llegan a
  `gateway.scan-outcomes` vía el binding `scan.outcome.#`, aunque usa
  `basic_get` (no `basic_consume`) por ser un test de topología, no un
  consumidor de producción — de ahí que no sirva como referencia de la API
  de streaming/`ack`/`nack` que sí cubre este documento en §1.
- `broker/docs/architecture.md` — confirma en prosa que "el Gateway consume
  las tres" variantes de `ScanOutcome` vía `gateway.scan-outcomes`, y el
  diagrama de flujo Gateway↔Broker↔ms-nmap.
