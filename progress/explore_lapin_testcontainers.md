# Exploración: `testcontainers` 0.20 + `lapin` 2.5 para el test de integración de `scan_submission`

> Investigación para el Nivel 3 de `docs/verification.md` aplicado a la
> feature `scan_submission` (única responsabilidad de este documento: cómo
> levantar un `rabbitmq:management` real vía `testcontainers` y verificar
> que `gateway` publica un `ScanRequest` válido en `scan.requests` / routing
> key `scan.request`, consumible desde una cola de test).
>
> **Atajo usado, tal como pidió la tarea**: el repo hermano `broker/` ya
> resolvió este mismo problema. Fuentes citadas, no reescritas:
> - `broker/progress/explore_lapin_testcontainers.md` (550 líneas)
> - `broker/progress/explore_definitions_format.md` (692 líneas)
> - `broker/tests/topology_exists.rs` y `broker/tests/common/mod.rs`
> - `broker/docker-compose.yml`, `broker/rabbitmq/rabbitmq.conf`
>
> Todo lo marcado "verificado localmente" viene de leer el código fuente
> vendored en `~/.cargo/registry/src/.../testcontainers-0.20.1` y
> `lapin-2.5.5` (exactamente las versiones que ya fija `gateway/Cargo.toml`/
> `Cargo.lock`), no de la documentación de `broker/` (que investigó
> `testcontainers-modules` + `testcontainers ^0.27` + `lapin` 3.x — **versiones
> distintas a las de este repo**, ver §0).

## 0. Diferencia crítica de partida: `gateway` NO puede copiar el código de `broker/` literalmente

`broker/Cargo.toml` usa `testcontainers-modules` (feature `rabbitmq`) sobre
`testcontainers ^0.27` y `lapin` en su rama 3.x. **`gateway/Cargo.toml` fija
`testcontainers = "0.20"` (sin `testcontainers-modules`) y `lapin = "2"`**
(`Cargo.lock` resuelve `testcontainers 0.20.1` y `lapin 2.5.5` exactos). Son
mayores distintos con APIs distintas. Verificado leyendo el código fuente
real de esas dos versiones vendored localmente:

- `testcontainers-modules` **no está en `Cargo.toml` de `gateway`** y no
  hace falta añadirlo: `testcontainers` 0.20 trae `GenericImage`
  (`testcontainers::images::generic::GenericImage`, reexportado como
  `testcontainers::GenericImage`), suficiente para levantar
  `rabbitmq:<tag>-management` sin escribir un `Image` custom.
- `lapin` 2.5.5 (no 3.x) expone la misma forma que documenta `broker/`:
  `exchange_declare(&self, exchange: &str, kind: ExchangeKind, options, arguments)`,
  `Consumer: Stream<Item = Result<Delivery>>`,
  `Connection::connect(uri: &str, ConnectionProperties)` y
  `Connection::connect_with_config(uri, ConnectionProperties, OwnedTLSConfig, runtime)`
  — confirmado en `lapin-2.5.5/src/channel.rs` y `connection.rs`. Los
  fragmentos de `broker/progress/explore_lapin_testcontainers.md` §1a/§2/§5
  (declare/publish/consume/`is_amqp_soft_error`) aplican tal cual a `lapin`
  2.5.5, no hace falta traducir nada ahí.

## 1. Levantar `rabbitmq:<tag>-management` con `testcontainers` 0.20 (`GenericImage`)

API exacta verificada en
`~/.cargo/registry/src/.../testcontainers-0.20.1/src/images/generic.rs`,
`src/core/image/image_ext.rs`, `src/runners/async_runner.rs`:

```rust
use testcontainers::core::{IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

let container = GenericImage::new("rabbitmq", "4.3.5-management") // mismo tag que broker/docker-compose.yml
    .with_exposed_port(5672.tcp())
    .with_exposed_port(5671.tcp())  // AMQPS — ver §4, gateway SÍ lo necesita
    .with_exposed_port(15672.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Server startup complete"))
    .with_mount(Mount::bind_mount(definitions_path, "/etc/rabbitmq/definitions.json"))
    .with_mount(Mount::bind_mount(conf_path, "/etc/rabbitmq/rabbitmq.conf"))
    // + mounts de los 3 .pem de TLS, ver §4
    .start()
    .await
    .expect("el contenedor RabbitMQ debe arrancar");

let host = container.get_host().await?;               // url::Host
let amqp_port = container.get_host_port_ipv4(5672).await?;   // u16
let amqps_port = container.get_host_port_ipv4(5671).await?;  // u16
```

Puntos verificados en el código fuente, no inferidos:

- `GenericImage::new(name, tag)`, `.with_exposed_port(port)`,
  `.with_wait_for(wait_for)`, `.with_entrypoint(...)` son métodos propios de
  `GenericImage` (no de `ImageExt`). `.with_mount(...)`, `.with_tag(...)`,
  `.with_env_var(...)` vienen de `ImageExt` (idéntico a lo que documenta
  `broker/`, mismo trait en ambas versiones).
- `get_host_port_ipv4(internal_port: impl Into<ContainerPort>)`: `u16`
  implementa `From<u16> for ContainerPort` (`src/core/ports.rs:157`), así
  que `get_host_port_ipv4(5672)` compila directo, sin `.tcp()` — el `.tcp()`
  solo hace falta al declarar `with_exposed_port` (que sí pide
  `ContainerPort`, y `IntoContainerPort` da el método `.tcp()` sobre `u16`).
- `WaitFor::message_on_stdout("Server startup complete")` — el mismo
  mensaje de log que usa `testcontainers-modules::rabbitmq::RabbitMq`
  internamente (confirmado en la fuente que citó `broker/`); con
  `GenericImage` hay que pasarlo explícitamente porque no hay imagen
  dedicada que lo traiga por defecto.
- **No hace falta `.with_exposed_port(...)` para que el puerto se publique**:
  `async_runner.rs` fija `host_config.publish_all_ports = Some(true)`
  incondicionalmente (verificado en el código, línea ~170) — Docker publica
  automáticamente *todos* los puertos que la imagen ya declara vía `EXPOSE`
  en su Dockerfile (la imagen oficial `rabbitmq:*-management` expone 4369,
  5671, 5672, 15672, 25672, entre otros). `.with_exposed_port(...)` solo es
  necesario si un puerto no está ya declarado en la imagen — no es el caso
  aquí, pero se recomienda declararlo explícitamente igual (5672, 5671,
  15672) por legibilidad/intención, tal como hace `broker/` con su propio
  `Image`.
- Timeout de arranque: `AsyncRunner` usa `DEFAULT_STARTUP_TIMEOUT = 60s`
  salvo que se llame a `.with_startup_timeout(...)` (otro método de
  `ImageExt`) — no hace falta tocarlo, 60s es suficiente para
  `rabbitmq:management` en CI según la experiencia ya documentada por
  `broker/`.

## 2. Cómo aplicar la topología: copiar `definitions.json` (+ `rabbitmq.conf`) literalmente, igual que decide `broker/`

`gateway/docs/architecture.md` (§"Comunicación con el Broker") ya fija la
decisión: *"El fixture de topología usado en tests de integración se copia
literalmente de `broker/rabbitmq/definitions.json` ... no se re-deriva"*.
`gateway/docs/verification.md` (Nivel 3, sección `broker`) lo confirma para
este repo. Mecanismo (idéntico al que `broker/progress/explore_definitions_format.md`
§0 y `broker/rabbitmq/rabbitmq.conf` ya validaron, no hace falta
re-investigarlo):

- **No existe `RABBITMQ_LOAD_DEFINITIONS`** en la imagen oficial (es de
  Bitnami). Se monta `definitions.json` + un `rabbitmq.conf` con la línea
  `load_definitions = /etc/rabbitmq/definitions.json` (clave **sin**
  prefijo `management.` — `management.load_definitions` falla en el primer
  arranque, ver docker-library/rabbitmq#428, ya documentado por `broker/`).
- Acción concreta para el implementer de `gateway`: crear
  `rabbitmq/definitions.json` en este repo como **copia literal** de
  `broker/rabbitmq/definitions.json` (mismo vhost `security-app`, mismos
  exchanges/colas/bindings, mismos usuarios `lab-admin`/`gateway`/`ms-nmap`/
  `ms-analisis` con sus contraseñas/hashes de laboratorio) — no
  re-derivarlo a mano. `gateway` solo necesita permisos verificables del
  usuario `gateway` (`write` en `scan.requests`/`scan.cancellations`,
  `read` en `gateway.scan-outcomes`, `configure: "^$"`), pero como la regla
  documentada es copiar el archivo completo (no un subconjunto), se copia
  entero — mantiene una única fuente de verdad si `broker/` cambia la
  topología.

### Punto importante que NO estaba en la premisa de la tarea: `rabbitmq.conf` de `broker/` exige TLS incondicionalmente

`broker/rabbitmq/rabbitmq.conf` (leído directamente) declara
`listeners.ssl.default = 5671` y las tres rutas `ssl_options.cacertfile/
certfile/keyfile` **sin condicionarlas a ninguna feature** — y
`broker/tests/common/mod.rs` deja constancia explícita en un comentario: *"el
nodo RabbitMQ no arranca en absoluto (ni siquiera para servir el listener
AMQP en claro de 5672) si esos archivos no existen"*. Si `gateway` copia
`rabbitmq.conf` literal junto con `definitions.json` (coherente con "no se
re-deriva la topología"), **el contenedor de test no arrancará** sin
también copiar/montar los 3 `.pem` de `broker/rabbitmq/tls/` (o generar los
propios con el mismo script `broker/rabbitmq/generate-lab-certs.sh`). Esto
es relevante incluso si el test solo quisiera hablar AMQP en claro — ver
§4, donde además se argumenta por qué `gateway` sí debe usar AMQPS también
en el test, no solo por esta restricción del arranque del contenedor.

## 3. Cola de verificación ad-hoc del TEST, declarada con `lab-admin` (nunca con el usuario `gateway`)

Dato clave que no aparece en la investigación de `broker/` porque no le
aplica a él de la misma forma: **el usuario `gateway` tiene `configure: "^$"`**
en `definitions.json` (verificado: `broker/rabbitmq/definitions.json`,
bloque de permisos de `"user": "gateway"` → `"configure": "^$"`, `"write":
"^scan\\.(requests|cancellations)$"`, `"read": "^gateway\\.scan-outcomes$"`).
Esto significa que el código de producción (`gateway`, conectado como el
usuario `gateway`) **no puede declarar nada** — ni la cola de verificación
del test ni ningún binding. Esto es intencional (mínimo privilegio, ver
`docs/security-scope.md`) y el test debe respetarlo: si el código de
producción intentara `queue_declare`/`exchange_declare`/`queue_bind`, el
test de "camino feliz" fallaría con `ACCESS_REFUSED` (403) — lo cual sería
correcto, porque `src/broker.rs` de `gateway` **solo debe llamar a
`basic_publish`**, nunca declarar topología (ya la trae `definitions.json`).

Patrón recomendado para el test (dos conexiones separadas, cada una con el
usuario que le corresponde):

```rust
// Conexión 1: como el usuario "gateway" — la que usará el código de
// producción (src/broker.rs) para publicar. Nunca declara nada.
let gateway_conn = connect_as(&container, "gateway", GATEWAY_LAB_PASSWORD).await;

// Conexión 2: como "lab-admin" (permisos completos) — SOLO para que el
// TEST se prepare una cola de verificación ad-hoc, algo que "gateway" no
// puede hacer y que en producción tampoco haría.
let admin_conn = connect_as(&container, "lab-admin", ADMIN_LAB_PASSWORD).await;
let admin_channel = admin_conn.create_channel().await?;

admin_channel
    .queue_declare(
        "test.scan-requests-verify",
        QueueDeclareOptions { durable: false, auto_delete: true, ..Default::default() },
        FieldTable::default(),
    )
    .await?;

admin_channel
    .queue_bind(
        "test.scan-requests-verify",
        "scan.requests",         // exchange real de definitions.json
        "scan.request",          // routing key real del contrato
        QueueBindOptions::default(),
        FieldTable::default(),
    )
    .await?;

let mut consumer = admin_channel
    .basic_consume(
        "test.scan-requests-verify",
        "test-consumer",
        BasicConsumeOptions::default(),
        FieldTable::default(),
    )
    .await?;

// --- Aquí es donde el implementer invoca el código de PRODUCCIÓN de
//     gateway (p. ej. gateway::broker::publish_scan_request(&gateway_conn, ...)
//     o el flujo HTTP completo de scan_submission vía POST /api/scans),
//     que internamente publica en "scan.requests" / "scan.request" ---

let delivery = tokio::time::timeout(Duration::from_secs(5), consumer.next())
    .await
    .expect("no debe hacer timeout")
    .expect("debe llegar un mensaje")
    .expect("sin error de protocolo");

let scan_request: serde_json::Value = serde_json::from_slice(&delivery.data)?;
assert_eq!(scan_request["ip"], "10.0.0.5");
// ... resto de campos exigidos por contracts/scan-request.schema.json:
// correlation_id, network_user, ssh_credentials_ref, has_sudo, requested_by
// (additionalProperties: false — también vale la pena assertar que NO
// aparecen claves extra).

delivery.ack(BasicAckOptions::default()).await?;
```

`test.scan-requests-verify` es una cola **puramente de test**, con
`auto_delete: true` (se limpia sola al cerrar el canal) — distinto de la
topología real que `definitions.json` fija y que el código de producción
nunca redeclara (coherente con la instrucción de la tarea: "esto es código
de TEST, no de producción").

Nombres/contraseñas de laboratorio ya documentados en
`gateway/docs/security-scope.md` (tabla de credenciales, copiada de
`broker/`): `lab-admin` / `lab-only-not-a-real-secret`, `gateway` /
`lab-only-not-a-real-secret-gateway`. No hace falta parsear
`definitions.json` en tiempo de test para obtenerlas — ya están en texto
plano en ese doc (son credenciales de laboratorio, nunca un secreto real).

Payload de ejemplo, válido contra `broker/contracts/scan-request.schema.json`
(leído directamente): objeto con `correlation_id`, `ip` (IPv4 o IPv6),
`network_user`, `ssh_credentials_ref`, `has_sudo` (bool), `requested_by`,
todos requeridos, `additionalProperties: false`.

## 4. ¿AMQPS también en el test, o vale AMQP en claro?

**Recomendación: sí, usar AMQPS (5671) también en el test del camino
feliz**, por tres motivos concretos (no solo "por si acaso"):

1. `gateway/docs/security-scope.md` (línea 54, leída directamente) es
   categórica: *"Toda conexión al Broker usa AMQPS (TLS), nunca el puerto
   AMQP en claro que `broker/docker-compose.yml` documenta como 'solo
   depuración local'"*. Esto aplica al **código de producción**
   (`src/broker.rs`), y el test de Nivel 3 de `scan_submission` debe
   ejercer ese código de producción tal cual, no una versión relajada.
2. `src/config.rs` (leído directamente) ya expone `broker_amqps_url` como
   un `SecretString` libre, leído de la env var `BROKER_AMQPS_URL` — no
   hay ninguna validación de esquema en `config.rs` que impida pasar una
   URL `amqp://` en un test, **pero** el propósito documentado del campo es
   siempre AMQPS; usar el contenedor de test por su puerto 5671 real
   (no 5672) es lo que hace que el test verifique el código de producción
   de verdad, no un atajo.
3. Si `gateway` copia `rabbitmq.conf` de `broker/` literal (§2), el
   contenedor **no arranca sin los certificados TLS montados** — así que,
   una vez resuelto ese requisito de arranque, usar 5671 en vez de 5672 no
   cuesta nada extra.

Patrón de conexión AMQPS, verificado que aplica a `lapin` 2.5.5 (misma API
que documentó `broker/` para 3.x — `Connection::connect_with_config` con
`OwnedTLSConfig` existe igual en 2.5.5, confirmado en
`lapin-2.5.5/src/connection.rs`):

```rust
use lapin::tcp::OwnedTLSConfig;
use lapin::{Connection, ConnectionProperties};

let uri = format!("amqps://gateway:{GATEWAY_LAB_PASSWORD}@{host}:{amqps_port}/security-app");
let ca_pem = std::fs::read_to_string(tls_dir.join("ca_certificate.pem"))?;
let tls_config = OwnedTLSConfig { identity: None, cert_chain: Some(ca_pem) };

let connection = Connection::connect_with_config(
    &uri,
    ConnectionProperties::default(),
    tls_config,
    lapin::runtime::default_runtime()?,
)
.await?;
```

### Gotcha de `rustls` (el mismo que documentó `broker/`, verificado si aplica a `gateway` o no)

`broker/tests/common/mod.rs` documenta un bug real: cuando el binario de
test trae **dos proveedores criptográficos `rustls` compilados para la
misma versión mayor de `rustls`** (`ring` y `aws_lc_rs` a la vez), la
primera conexión AMQPS **no falla, se cuelga para siempre** (el hilo
`lapin-io-loop` hace panic en un hilo separado que nadie observa) —
`rustls::crypto::<backend>::default_provider().install_default()` una sola
vez por proceso lo resuelve.

**Verificación concreta para `gateway`** (no asumida, comprobada leyendo
`Cargo.lock` de este repo): las dependencias que traen `rustls` en
`gateway` son `bollard` (vía `testcontainers`, usa `rustls 0.22.4`) y
`reqwest` + `rustls-connector` (vía `lapin` con feature `rustls`, ambas en
`rustls 0.23.45`). **En el `Cargo.lock` actual solo aparece el paquete
`ring`** como backend criptográfico — no aparece `aws-lc-rs` en absoluto.
Como `bollard` está en la rama `0.22.4` (un `CryptoProvider::install_default`
global distinto al de `0.23.x`) y dentro de `0.23.45` solo hay un candidato
(`ring`), **hoy `gateway` no debería reproducir el cuelgue que sí sufrió
`broker/`** (que sí mezclaba `aws_lc_rs` y `ring` dentro de la misma rama
`rustls`). Esto puede cambiar si el implementer añade
`testcontainers-modules` u otra dependencia que arrastre `aws-lc-rs` — por
eso, aun así, se recomienda instalar el provider explícitamente como medida
defensiva barata (mismo patrón que `broker/`, añadiendo `rustls = "0.23"`
como dev-dependency directa si no compila sin ella):

```rust
static INIT: std::sync::Once = std::sync::Once::new();
INIT.call_once(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
});
```

(Nota: usar `ring::default_provider()`, no `aws_lc_rs::default_provider()`
como hace `broker/` — en `gateway` el backend presente en `Cargo.lock` es
`ring`, no `aws_lc_rs`; instalar el backend que no está compilado no
soluciona nada. Si tras implementar la feature `cargo tree -i aws-lc-rs`
muestra resultados, cambiar a `aws_lc_rs::default_provider()` en su lugar.)

## Resumen para el implementer

| Pregunta | Respuesta |
|---|---|
| ¿Qué imagen de `testcontainers` usar? | `testcontainers::GenericImage` (0.20, ya en `Cargo.toml`) — **no** `testcontainers-modules` (no está declarado, no hace falta añadirlo). |
| ¿Tag de imagen? | `4.3.5-management`, igual a `broker/docker-compose.yml`. |
| ¿Puertos? | No fijar host ports; `publish_all_ports=true` es automático. Usar `get_host_port_ipv4(5672\|5671\|15672)` tras `start()`. |
| ¿Cómo cargar la topología? | Copiar literalmente `broker/rabbitmq/definitions.json` a `gateway/rabbitmq/definitions.json`, montarlo + un `rabbitmq.conf` con `load_definitions = /etc/rabbitmq/definitions.json` (sin prefijo `management.`). |
| ¿Hace falta copiar `rabbitmq.conf`/TLS de `broker/` también? | Si se copia el `rabbitmq.conf` de `broker/` tal cual, **sí** — ese archivo exige TLS incondicionalmente o el nodo no arranca. Copiar también `broker/rabbitmq/tls/*.pem` (o regenerarlos con `generate-lab-certs.sh`). |
| ¿Quién declara la cola de verificación del test? | `lab-admin` (permisos completos), **nunca** el usuario `gateway` — `gateway` tiene `configure: "^$"`, solo puede publicar. |
| ¿AMQP en claro (5672) o AMQPS (5671) en el test? | AMQPS, para ejercer el mismo camino que exige `docs/security-scope.md` en producción. El contenedor ya lo expone si se copia `rabbitmq.conf`/TLS de `broker/`. |
| ¿Bug de `rustls`? | El mismo de `broker/` es posible pero, según el `Cargo.lock` actual de `gateway` (solo `ring`, no `aws-lc-rs`), no debería reproducirse hoy. Instalar el provider explícitamente igual, como medida defensiva barata. |

## Fuentes

- `broker/progress/explore_lapin_testcontainers.md`,
  `broker/progress/explore_definitions_format.md`,
  `broker/tests/topology_exists.rs`, `broker/tests/common/mod.rs`,
  `broker/docker-compose.yml`, `broker/rabbitmq/rabbitmq.conf`,
  `broker/rabbitmq/definitions.json` (citados, no reescritos).
- Código fuente vendored local (leído directamente, no vía docs.rs):
  `~/.cargo/registry/src/index.crates.io-*/testcontainers-0.20.1/src/{lib.rs,core.rs,core/image.rs,core/image/image_ext.rs,core/mounts.rs,core/ports.rs,core/wait/mod.rs,images/generic.rs,runners/async_runner.rs}`,
  `~/.cargo/registry/src/index.crates.io-*/lapin-2.5.5/src/{channel.rs,connection.rs,consumer.rs}`.
- `gateway/Cargo.toml`, `gateway/Cargo.lock`, `gateway/src/config.rs`,
  `gateway/src/lib.rs`, `gateway/src/domain.rs`,
  `gateway/docs/architecture.md`, `gateway/docs/verification.md`,
  `gateway/docs/security-scope.md`, `gateway/feature_list.json`
  (feature 6, `scan_submission`).
- `broker/contracts/scan-request.schema.json` (shape exacto del
  `ScanRequest`).
