# Explore: `lapin` publish (AMQPS) para `gateway` — feature `scan_submission`

> Investigación de solo-lectura (no toca `Cargo.toml`/`src/`/`tests/`). Cubre
> únicamente **publicar** (`basic_publish`), no consumir (eso es la feature
> `scan_outcomes_consumer`, fuera de alcance aquí).

## 0. HALLAZGO CRÍTICO: `gateway` fija `lapin = "2"`, NO `"4"` como `broker`

El repo hermano `broker` (`../broker/progress/explore_lapin_tls.md`, 866
líneas) investigó `lapin = "4.11.0"` — es la versión que ese repo fija en su
`Cargo.toml`. **`gateway/Cargo.toml` fija `lapin = { version = "2", features
= ["rustls"], default-features = false }`**, y `Cargo.lock` de este repo
resuelve exactamente a **`lapin 2.5.5`** (`amq-protocol 7.2.3`,
`amq-protocol-tcp 7.2.3`, `tcp-stream 0.28.0`) — confirmado leyendo
`gateway/Cargo.lock` y el código fuente real en
`~/.cargo/registry/src/.../lapin-2.5.5/` (ambas versiones, 2.5.5 y 4.11.0,
están cacheadas localmente, así que todo lo que sigue está verificado contra
el **código fuente real de 2.5.5**, no contra la doc de `broker` ni contra
docs.rs).

**La API de conexión de `broker/explore_lapin_tls.md` NO aplica literalmente
aquí** (`connect_with_config` en v2 no recibe un `Runtime<RK>` como 4º
argumento; el manejo de executor/reactor es distinto — ver §3). Los
conceptos de alto nivel sí transfieren (AMQPS por esquema de URI,
`OwnedTLSConfig`, publisher confirms, no hace falta declarar topología), pero
cada firma de tipo/método debe tomarse de este documento, no del de `broker`.

**Cargo.toml — confirmación del feature flag actual:** `lapin` 2.5.5 tiene
`default = ["rustls"]` y `rustls = ["rustls-native-certs"]` (confirmado en
`lapin-2.5.5/Cargo.toml` y `amq-protocol-tcp-7.2.3/Cargo.toml`, sección
`[features]`). El `Cargo.toml` de `gateway` usa `default-features = false,
features = ["rustls"]`, que activa exactamente esa misma cadena
(`rustls` → `rustls-native-certs` en ambos crates) — **es correcto y
suficiente** para AMQPS con verificación contra el almacén de certificados
nativo del SO/contenedor (útil para un proveedor de RabbitMQ con AMQPS y
cert firmado por una CA pública, p. ej. CloudAMQP o un RabbitMQ propio con
cert de una CA reconocida). Si en el futuro se necesitara confiar en una CA
de laboratorio autofirmada (como hace `broker` en sus tests), el mecanismo
es el mismo `OwnedTLSConfig.cert_chain: Option<String>` (ver §2), pero eso
no hace falta tocarlo en `Cargo.toml`.

---

## 1. Qué necesita `gateway` para publicar (resumen ejecutivo)

1. **`Cargo.toml`: ningún cambio en `lapin`.** Lo que ya está
   (`lapin = { version = "2", features = ["rustls"], default-features =
   false }`) es correcto y suficiente para AMQPS con CA pública/estándar.
2. **Falta añadir 2 dependencias nuevas** si se quiere que `lapin` use el
   runtime `tokio` que ya usa todo el resto de `gateway` (axum) en vez de su
   propio pool de hilos (`async-global-executor`, que ya está en
   `Cargo.lock` como dependencia transitiva pero por defecto, no integrada
   con tokio): `tokio-executor-trait` y `tokio-reactor-trait` (ver §3.1 —
   son *dev-dependencies* de `lapin` mismo, no dependencias normales, así
   que `gateway` debe declararlas explícitamente en su propio `Cargo.toml`
   como dependencias normales).
3. **Conexión persistente, no una por request** (§5): abrir `Connection` +
   `Channel` una vez al arrancar (o de forma perezosa en el primer publish)
   y guardarlos en `AppState` como `Arc<Channel>` (patrón ya usado en este
   repo para `usuarios_client`/`oidc_client`, ver `src/api.rs`).
4. **Publisher confirms — recomendación: NO esperarlos en el hot path del
   `POST /api/scans`** dado el límite RNF-04 (<500 ms). Usar
   `confirm_select` en el canal persistente al inicializar (una sola vez),
   publicar con `basic_publish(...).await?` (esto ya confirma que el
   *frame* se envió y el canal seguía vivo) y tratar el
   `Result<PublisherConfirm>` como éxito de "encolado", sin awaitear el
   segundo `.await` que espera el ack/nack real del broker — ver
   trade-off detallado en §4.
5. **No hace falta declarar el exchange `scan.requests`** antes de publicar
   — `basic_publish` no lo requiere, ver §6 (confirmado leyendo el código
   fuente de `basic_publish` en `lapin` 2.5.5).
6. **Errores de `lapin`**: un único enum `lapin::Error` (`#[non_exhaustive]`,
   `Clone + Debug`, NO implementa `PartialEq` de forma útil para
   `IOError`/`SerialisationError`) con 9 variantes — ver §7 para el mapeo a
   un `BrokerError` propio con `thiserror`.

---

## 2. Conectar por AMQPS — API exacta de `lapin` 2.5.5

Código real, `lapin-2.5.5/src/connection.rs`:

```rust
impl Connection {
    pub async fn connect(uri: &str, options: ConnectionProperties) -> Result<Connection> {
        Connect::connect(uri, options, OwnedTLSConfig::default()).await
    }

    pub async fn connect_with_config(
        uri: &str,
        options: ConnectionProperties,
        config: OwnedTLSConfig,
    ) -> Result<Connection> {
        Connect::connect(uri, options, config).await
    }
    // + connect_uri / connect_uri_with_config (mismo par, recibiendo AMQPUri ya parseado)
}
```

Nótese: **no hay parámetro `Runtime<RK>`** en v2.5.5 (eso es solo v4.x, ver
§0). El runtime/executor se configura vía `ConnectionProperties`, no como
argumento de `connect` (ver §3).

`OwnedTLSConfig` (re-exportado por `lapin::tcp`, viene de
`amq-protocol-tcp` → `tcp-stream` 0.28.0):

```rust
pub struct OwnedTLSConfig {
    pub identity: Option<OwnedIdentity>, // solo mTLS cliente — no aplica aquí
    pub cert_chain: Option<String>,      // PEM de CA extra; None = solo almacén nativo del SO
}
```

El esquema de la URI decide TLS, no una opción aparte — confirmado en
`amq-protocol-tcp-7.2.3/src/lib.rs`:

```rust
let stream = match self.scheme {
    AMQPScheme::AMQP => stream,
    AMQPScheme::AMQPS => stream.into_tls(&self.authority.host, config)?,
};
```

Para `gateway`, con `config.broker_amqps_url` ya cargado como
`SecretString` (`src/config.rs`, ya usa el esquema `amqps://...` — ver
`LAB_BROKER_AMQPS_URL` en los tests de ese archivo) y sin necesidad de CA
custom (§0):

```rust
use lapin::{Connection, ConnectionProperties};
use secrecy::ExposeSecret;

async fn connect(amqps_url: &secrecy::SecretString) -> lapin::Result<Connection> {
    let options = ConnectionProperties::default()
        .with_executor(tokio_executor_trait::Tokio::current())
        .with_reactor(tokio_reactor_trait::Tokio);

    Connection::connect(amqps_url.expose_secret(), options).await
}
```

(Si más adelante hiciera falta una CA de laboratorio para tests de
integración locales, se usa `Connection::connect_with_config(uri, options,
OwnedTLSConfig { identity: None, cert_chain: Some(ca_pem) })` — mismo patrón
que documentó `broker`, solo sin el 4º argumento `Runtime<RK>`.)

---

## 3. Runtime/executor: por qué hace falta `tokio-executor-trait` +
   `tokio-reactor-trait`

### 3.1 Comportamiento por defecto sin configurarlo

`ConnectionProperties::default()` deja `executor: None, reactor: None`.
Código real, `lapin-2.5.5/src/connection.rs`, `Connection::connector`:

```rust
let executor = options
    .executor
    .take()
    .unwrap_or_else(|| Arc::new(async_global_executor_trait::AsyncGlobalExecutor));
```

Es decir: si `gateway` no configura nada, `lapin` usa por defecto
`async-global-executor` (su propio pool de hilos, vía la crate
`async-global-executor-trait`) en vez del runtime `tokio` que ya usa todo
axum/el resto del servicio. Esto **funciona**, pero mezcla dos runtimes
async distintos en el mismo proceso (más overhead, dos pools de hilos, y
la lib de tracing de `lapin` interactúa peor con `tokio-console`/métricas
si en el futuro se instrumentan). `async-global-executor-trait` y
`async-global-executor` ya están en `gateway/Cargo.lock` como dependencias
transitivas de `lapin`, así que compila sin cambios — pero no es el patrón
recomendado para un servicio `axum`/`tokio` de alta concurrencia.

### 3.2 Patrón recomendado — igual que el ejemplo oficial `examples/tokio.rs`
   de `lapin` 2.5.5

```rust
let options = ConnectionProperties::default()
    .with_executor(tokio_executor_trait::Tokio::current())
    .with_reactor(tokio_reactor_trait::Tokio);
```

**Estas dos crates (`tokio-executor-trait`, `tokio-reactor-trait`) NO están
hoy en `gateway/Cargo.lock`** — son *dev-dependencies* del propio `lapin`
(usadas solo en sus ejemplos/tests), no dependencias normales que arrastre
transitivamente un consumidor. `gateway` debe añadirlas explícitamente como
dependencias normales en su `Cargo.toml` para poder usar este patrón (nota
para el implementer: esto es un cambio de `Cargo.toml`, no de código de
`src/`/`tests/`, así que cae fuera de la restricción "no editar src/tests"
del leader — pero sigue siendo una decisión de la feature `scan_submission`,
no de `config`/`crate_setup`, así que documentarlo en el PR).

### 3.3 Reconexión — `lapin` NO reconecta solo

Confirmado leyendo `connection_status.rs`/`connection.rs`: no existe ningún
mecanismo de retry/reconexión automática dentro de `lapin` 2.5.5. Lo único
que expone es:

```rust
impl Connection {
    pub fn on_error<E: FnMut(Error) + Send + 'static>(&self, handler: E);
    pub fn status(&self) -> &ConnectionStatus; // .connected() -> bool
}
```

El propio ejemplo oficial `examples/reconnect.rs` de `lapin` implementa la
reconexión "a mano": detecta el error (`Result::Err` al hacer cualquier
operación, o vía `on_error`), y vuelve a llamar a `Connection::connect(...)`
desde cero tras un `sleep`. Para `gateway` esto importa para §5 (patrón de
conexión persistente): el publisher debe poder detectar un canal/conexión
muerta y reabrir, no asumir que el `Arc<Channel>` guardado en `AppState`
sigue siendo válido para siempre.

---

## 4. `basic_publish`, publisher confirms y el trade-off de RNF-04 (<500ms)

### 4.1 Firma exacta (`lapin-2.5.5/src/generated.rs`, delegado desde `Channel`)

```rust
pub async fn basic_publish(
    &self,
    exchange: &str,
    routing_key: &str,
    options: BasicPublishOptions,   // { mandatory: bool, immediate: bool }
    payload: &[u8],
    properties: BasicProperties,
) -> Result<PublisherConfirm>
```

`PublisherConfirm` implementa `Future<Output = Result<Confirmation>>`.
`Confirmation` es `Ack(Option<Box<BasicReturnMessage>>) | Nack(...) |
NotRequested`.

Dos niveles de espera, confirmados en el ejemplo oficial
`examples/publisher_confirms.rs`:

```rust
// Nivel 1: el frame se envió y el canal seguía conectado. RÁPIDO
// (no espera respuesta del broker), pero NO confirma que el broker
// aceptó/enrutó el mensaje.
let publisher_confirm = channel.basic_publish(
    "scan.requests", "scan.request",
    BasicPublishOptions::default(),
    &payload_json,
    BasicProperties::default().with_content_type("application/json".into()),
).await?; // <- Result<PublisherConfirm>

// Nivel 2 (opcional): esperar el ack/nack real del broker. LENTO
// (round-trip de red hasta RabbitMQ), solo tiene efecto si el canal
// llamó antes a confirm_select().
let confirmation = publisher_confirm.await?; // <- Result<Confirmation>
assert!(confirmation.is_ack());
```

`confirm_select` (una sola vez por canal, antes de publicar nada):

```rust
channel.confirm_select(lapin::options::ConfirmSelectOptions::default()).await?;
```

### 4.2 Trade-off para `POST /api/scans` (RNF-04: respuesta <500ms)

- **Sin `confirm_select`** (`Confirmation::NotRequested` siempre): el
  `.await` de `basic_publish` solo espera que el *frame* AMQP salga por el
  socket — típicamente sub-milisegundo si la conexión TCP/TLS ya está
  establecida (conexión persistente, §5). No hay garantía de que RabbitMQ
  lo haya persistido/enrutado. Si el broker rechaza el mensaje (p. ej.
  routing sin cola bindeada, con `mandatory: true`) eso se reporta de forma
  **asíncrona** vía `basic_return`, no en este `.await`.
- **Con `confirm_select` + esperar el segundo `.await`**: garantiza que
  RabbitMQ efectivamente aceptó (`ack`)/rechazó (`nack`) el mensaje antes de
  responder al cliente HTTP — más seguro para no dejar un `scanId` "fantasma"
  que el usuario cree encolado pero nunca llegó al broker. Coste: un
  round-trip de red adicional gateway↔RabbitMQ antes de poder responder el
  `POST`.

**Recomendación concreta para `scan_submission`:**

1. Llamar a `confirm_select` **una sola vez**, al crear el canal persistente
   (no en cada request) — así el canal ya opera en modo confirms para
   siempre, sin coste extra de handshake por publish.
2. En el hot path del handler, **sí esperar el ack/nack** (`publisher_confirm
   .await?`), no solo el primer nivel. Justificación: RNF-04 pide <500ms, no
   "instantáneo", y un ack de RabbitMQ en la misma red privada (broker en
   subred privada, gateway habla directo con él) es típicamente de un solo
   dígito de milisegundos — muy por debajo del presupuesto. La alternativa
   (no esperar) ahorra esos pocos ms pero abre la ventana descrita en
   `feature_list.json` línea 93 ("un fallo al publicar en el Broker tras
   haber registrado el histórico se refleja actualizando a Fallido") — sin
   el ack no hay forma fiable de distinguir "se publicó" de "se envió el
   frame pero el broker lo rechazó", lo cual es justo el caso que esa
   entrada de `feature_list.json` exige poder detectar.
3. Documentar esta decisión explícitamente en el código (comentario) porque
   es un trade-off de latencia vs. certeza, no un hecho técnico único —
   si en producción el ack añadiera latencia observable, se puede revisar.

---

## 5. Conexión/canal persistente en `AppState` — patrón recomendado para
   axum de alta concurrencia

**Sí, conexión y canal persistentes, reutilizados entre requests — no una
conexión nueva por publish.** Razones:

- Abrir una `Connection` AMQPS implica handshake TCP + TLS + handshake AMQP
  (`Connection.Start`/`Tune`/`Open`) — varias decenas de ms típicamente, muy
  caro para hacerlo dentro del presupuesto de 500ms de cada `POST
  /api/scans`, y completamente innecesario si se puede reutilizar.
- `lapin::Channel` es `Clone` y seguro para compartir entre tasks (usa
  internamente `flume`/`parking_lot` — confirmado por las dependencias
  declaradas en `Cargo.toml` de `lapin`, y es justamente el patrón que sus
  propios ejemplos muestran con `channel_a`/`channel_b` usados desde
  distintas tasks concurrentes).
- Ya es el patrón que este repo usa para los otros clientes externos:
  `AppState` en `src/api.rs` guarda `Arc<OidcClient>`, `Arc<UsuariosClient>`
  — un `Arc<lapin::Channel>` (o un wrapper propio, p. ej.
  `Arc<BrokerPublisher>` que internamente guarda el `Channel` + lógica de
  reconexión de §3.3) encaja en el mismo `AppState`.

Patrón concreto sugerido (para el implementer, no código de producción
aquí):

```rust
#[derive(Clone)]
pub struct AppState {
    // ... campos existentes (oidc_client, usuarios_client, ...)
    pub broker_channel: Arc<lapin::Channel>,
}
```

o, si se quiere encapsular la reconexión (recomendado dado §3.3 — `lapin` no
reconecta solo), un wrapper propio en `src/broker.rs`:

```rust
pub struct BrokerPublisher {
    channel: tokio::sync::RwLock<lapin::Channel>,
    // + lo necesario para reabrir: amqps_url, vhost, ConnectionProperties...
}

impl BrokerPublisher {
    pub async fn publish(&self, exchange: &str, routing_key: &str, body: &[u8]) -> Result<(), BrokerError> {
        // intenta publicar con el channel actual; si detecta
        // InvalidChannelState/IOError, reconecta (Connection::connect desde
        // cero, ver §3.3) y reintenta una vez.
    }
}
```

Esto es una decisión de diseño para el implementer de `scan_submission`
(o de una feature previa dedicada a `broker_publisher` si el leader decide
partirla), no algo que este documento de exploración deba fijar en detalle.

**Comparación con `broker/`:** el repo `broker` NO tiene este problema
porque no es un servicio HTTP de larga vida — es un crate de
verificación/tests que abre una conexión nueva por cada test
(`tests/common/mod.rs`, contenedor `testcontainers` efímero). No hay
patrón de "conexión persistente en `AppState`" que copiar de ahí porque
`broker` no tiene un `AppState` ni sirve tráfico HTTP continuo — es la
diferencia arquitectónica clave entre ambos repos para este punto.

---

## 6. No hace falta declarar el exchange antes de publicar

Confirmado leyendo el cuerpo real de `basic_publish` en
`lapin-2.5.5/src/generated.rs` (líneas ~624 en adelante): la función arma un
frame `Basic.Publish` con `exchange`/`routing_key`/propiedades y lo escribe
al socket — en ningún punto llama a `exchange_declare` ni valida localmente
que el exchange exista en el canal. La existencia del exchange es
responsabilidad exclusiva del servidor RabbitMQ en el momento de enrutar el
mensaje:

- Si el exchange **existe** (como ya lo hace, vía
  `broker/rabbitmq/definitions.json`, aplicado al arrancar RabbitMQ — fuera
  del código de este repo, tal como indica la tarea): el publish funciona
  normalmente, sin que `gateway` lo haya declarado nunca en ningún canal.
- Si el exchange **no existiera**, RabbitMQ cerraría el **canal** (no la
  conexión) con un error protocolo `NOT_FOUND` (404) — eso se vería como un
  `lapin::Error::ProtocolError`/`InvalidChannelState` en la siguiente
  operación sobre ese canal, no como un rechazo síncrono de `basic_publish`
  mismo (AMQP 0-9-1 es asíncrono a nivel de frame: el servidor cierra el
  canal con un frame `Channel.Close` que `lapin` traduce a error en la
  próxima llamada). No es el caso esperado aquí porque la topología ya la
  gestiona `broker/`, pero es la razón por la que `gateway` **no debe**
  llamar a `exchange_declare`/`queue_declare` por su cuenta: sería
  redeclarar topología que no le pertenece (instrucción explícita de la
  tarea), y además, si la declaración no coincidiera exactamente en tipo
  (`topic` según `broker/rabbitmq/definitions.json`) o argumentos con lo que
  ya existe, RabbitMQ rechazaría *esa* declaración con un error de canal
  distinto (`PRECONDITION_FAILED`, 406) — un riesgo evitado simplemente no
  declarando nada del lado del publisher.

---

## 7. Mapeo de `lapin::Error` a un `BrokerError` propio con `thiserror`

`lapin::Error` (`lapin-2.5.5/src/error.rs`) es `#[non_exhaustive]`,
`Clone + Debug` (no `Copy`, no `PartialEq` útil para 2 de sus variantes) con
estas 9 variantes:

```rust
pub enum Error {
    ChannelsLimitReached,
    InvalidProtocolVersion(ProtocolVersion),
    InvalidChannel(ChannelId),
    InvalidChannelState(ChannelState),
    InvalidConnectionState(ConnectionState),
    IOError(Arc<io::Error>),
    ParsingError(ParserError),
    ProtocolError(AMQPError),      // errores AMQP del servidor, p.ej. NOT_FOUND/PRECONDITION_FAILED
    SerialisationError(Arc<GenError>),
    MissingHeartbeatError,
}
```

Implementa `std::error::Error` (con `source()` delegando a `IOError`/
`ParsingError`/`ProtocolError`/`SerialisationError`) y `From<io::Error>`.

Mapeo sugerido a un `BrokerError` propio (siguiendo el mismo patrón que ya
usa este repo en otros módulos — ver `UsuariosClientError` en
`src/usuarios_client.rs`, y el patrón general de `docs/conventions.md`:
variantes específicas con `thiserror`, nunca `String` genérico ni panics):

```rust
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("no se pudo conectar al Broker (AMQPS)")]
    ConnectionFailed(#[source] lapin::Error),

    #[error("no se pudo publicar en el exchange '{exchange}'")]
    PublishFailed {
        exchange: String,
        #[source] source: lapin::Error,
    },

    #[error("el Broker no confirmó la recepción del mensaje en el exchange '{exchange}' (nack)")]
    NotAcknowledged { exchange: String },

    #[error("no se pudo serializar el mensaje a JSON")]
    SerializationFailed(#[source] serde_json::Error),
}
```

Notas de mapeo:

- **Conexión inicial / reconexión** (§3.3, cualquier error de
  `Connection::connect`/`connect_with_config`) → `ConnectionFailed`. Cubre
  típicamente `Error::IOError` (TCP/TLS falló) y
  `Error::InvalidProtocolVersion`/`Error::MissingHeartbeatError`.
- **Cualquier error del propio `basic_publish(...).await?` (primer nivel)**
  → `PublishFailed { exchange, source }`. Cubre `Error::InvalidChannelState`
  (canal muerto — dispara la lógica de reconexión de §3.3 antes de
  reintentar), `Error::IOError`, `Error::ProtocolError` (p.ej. si el
  exchange no existiera, aunque no debería pasar — ver §6),
  `Error::SerialisationError` (fallo al generar el frame AMQP en sí, no el
  JSON del payload — no confundir con `SerializationFailed`, que es para
  `serde_json::to_vec(&scan_request)` **antes** de llegar a `lapin`).
- **`Confirmation::Nack(_)` tras esperar el segundo `.await`** (§4.2, si se
  adopta la recomendación de esperar el ack) → `NotAcknowledged { exchange
  }`. Esto NO es un `lapin::Error` — `Confirmation::Nack` es un `Ok(...)` a
  nivel de `Result<Confirmation>`, así que el mapeo lo hace el código de
  `gateway` explícitamente con un `match`, no un `From<lapin::Error>`.
- Ninguna variante debe usar `.unwrap()`/`.expect()`/`panic!` en código de
  `src/` — todo el árbol de errores de `lapin` ya llega como `Result`,
  así que basta propagar con `?` tras envolver con `.map_err(|e|
  BrokerError::PublishFailed { exchange: exchange.to_string(), source: e
  })`.

---

## 8. Fuentes citadas

- `lapin` 2.5.5 (versión REAL resuelta por `gateway/Cargo.lock`) —
  código fuente local:
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/lapin-2.5.5/`
  — `Cargo.toml`, `src/lib.rs`, `src/connection.rs`,
  `src/connection_properties.rs`, `src/connection_status.rs`,
  `src/error.rs`, `src/publisher_confirm.rs`, `src/generated.rs`
  (`basic_publish`, `confirm_select`, `BasicPublishOptions`),
  `examples/tokio.rs`, `examples/publisher_confirms.rs`,
  `examples/reconnect.rs`.
- `amq-protocol-tcp` 7.2.3 — código fuente local:
  `~/.cargo/registry/src/.../amq-protocol-tcp-7.2.3/src/lib.rs`
  (`AMQPUriTcpExt`, `OwnedTLSConfig` re-export, decisión TLS por esquema de
  URI).
- `gateway/Cargo.toml`, `gateway/Cargo.lock` (versión real resuelta),
  `gateway/src/config.rs` (`ENV_BROKER_AMQPS_URL`/`ENV_BROKER_VHOST`,
  `SecretString`), `gateway/src/api.rs` (patrón `AppState` con `Arc<...>`
  para clientes externos), `gateway/src/broker.rs` (stub vacío actual),
  `gateway/feature_list.json` (feature `scan_submission`: exchange
  `scan.requests`, routing key `scan.request`, exchange
  `scan.cancellations` para `ScanCancellation`).
- Contraste (NO aplicable literalmente por diferencia de versión mayor de
  `lapin`, ver §0): `broker/progress/explore_lapin_tls.md` (866 líneas,
  `lapin` 4.11.0), `broker/docs/architecture.md`, y
  `broker/tests/permissions.rs`/`outcome_routing.rs`/`cancellation.rs`
  (usos reales de `basic_publish` en ese repo, mismo patrón conceptual de
  llamada aunque sobre `lapin` 4.x).
