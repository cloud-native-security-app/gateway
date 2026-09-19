# Investigación: lado SSE/axum de `GET /api/scans/{scan_id}/events` (feature `scan_outcome_relay`)

> Alcance: SOLO el lado `axum`/SSE (handler, registro de fan-out en
> `realtime`, terminación del stream, testing, middleware de sesión). El
> consumidor de fondo de `gateway.scan-outcomes` (`lapin`) es investigación
> de otro agente en paralelo — no se toca aquí.

Todo lo siguiente está verificado contra el **código fuente real** vendorizado
en `~/.cargo/registry/src/.../axum-0.7.9` (no memoria/entrenamiento), y contra
el `Cargo.toml`/`Cargo.lock` reales de este repo (vía `cargo tree -e features`).

## 1. API exacta de `axum::response::sse` en axum 0.7.9

Fuente: `axum-0.7.9/src/response/sse.rs` (confirmado compatible con
`axum = "0.7"` ya fijado — este es el `Cargo.lock` real).

- `Sse::new(stream) -> Sse<S>` donde `S: TryStream<Ok = Event>, S::Error: Into<BoxError>`.
  En la práctica, para un handler normal, `S: Stream<Item = Result<Event, E>>`.
- `.keep_alive(KeepAlive)` (opcional): sin ella, no se envían comentarios de
  keep-alive; con proxies/balanceadores intermedios puede hacer falta para
  no cortar la conexión inactiva (`KeepAlive::default()` = cada 15s).
- `impl<S, E> IntoResponse for Sse<S> where S: Stream<Item = Result<Event, E>> + Send + 'static, E: Into<BoxError>`
  → pone `Content-Type: text/event-stream` y `Cache-Control: no-cache`
  automáticamente. Firma de handler idiomática:
  ```rust
  async fn scan_events(/* extractors */) -> Sse<impl Stream<Item = Result<Event, Infallible>>> { ... }
  ```
- `Event::default().data(json_string)` — también existe `.json_data(&T)` donde
  `T: Serialize`, que devuelve `Result<Event, axum_core::Error>` (falla solo
  si la serialización falla; **panics**, no `Err`, si se llama `.data()`/
  `.json_data()` dos veces sobre el mismo `Event`, o si el string contiene
  `\r`). `.json_data` requiere el feature `json` de `axum` — **ya activo**:
  `axum = "0.7"` en este `Cargo.toml` no desactiva default-features, y
  `json` está en `default = [...]` de `axum-0.7.9/Cargo.toml`. No hace falta
  tocar `Cargo.toml` por esto.
- `.event("nombre")` pone la línea `event: nombre` (dispara
  `addEventListener("nombre", ...)` en el cliente en vez de `onmessage`).
  Panic si se llama dos veces.
- Cada `Event` se serializa con un `\n\n` final (`finalize()`), es decir el
  propio tipo ya respeta el framing `text/event-stream` — no hay que
  construir las líneas a mano.

## 2. Patrón de fan-out (registro por `scan_id`) — `realtime.rs`

`src/realtime.rs` hoy solo tiene el doc-comment del módulo (vacío). No hay
`DashMap` en el árbol de dependencias (`Cargo.lock` no lo tiene) y **no
recomiendo añadirlo**: el volumen esperado es "N escaneos concurrentes de un
laboratorio", no miles de streams/seg — `std::sync::RwLock<HashMap<...>>`
protegido por secciones críticas puramente síncronas (sin `.await` dentro del
lock) es suficiente y sigue el mismo patrón ya aceptado en este repo para
`auth::LoginStateStore` (que usa `std::sync::Mutex<HashMap<...>>`, no
`tokio::sync::Mutex`, exactamente porque sus operaciones son síncronas).

Verificado con `cargo tree -e features -i tokio`: el feature `sync` de
`tokio` (necesario para `tokio::sync::broadcast` y `tokio::sync::RwLock`) **ya
está activo transitivamente** (vía `reqwest`/`hyper-util`), aunque el
`Cargo.toml` de este repo solo declara explícitamente
`features = ["rt-multi-thread", "macros"]` para `tokio`. Esto compila hoy,
pero es frágil (si algún día cambia la cadena de dependencias que lo activa
transitivamente, deja de compilar sin aviso). **Recomendación**: añadir
`"sync"` explícitamente a los features de `tokio` en `Cargo.toml`, por
explicitud, no porque falte hoy.

Diseño concreto propuesto para `realtime.rs`:

```rust
use std::collections::HashMap;
use std::sync::RwLock;

use tokio::sync::broadcast;

use crate::domain::ScanOutcomeEvent; // ya nombrado así en docs/architecture.md §Capas/domain

/// Capacidad del canal broadcast por `scan_id`: basta con un puñado de
/// eventos en vuelo (started/completed|failed) antes de que el/los
/// suscriptores los consuman; no es un búfer de histórico.
const CHANNEL_CAPACITY: usize = 16;

/// Registro en memoria de streams SSE activos por `scan_id`, y puente entre
/// el consumidor de fondo de `gateway.scan-outcomes` y esos streams.
///
/// **Limitación de diseño, aceptada, no sobre-ingenierizada**: una entrada
/// (`broadcast::Sender`) puede sobrevivir brevemente sin receivers vivos
/// (p. ej. el cliente SSE cerró la pestaña justo antes de que el
/// consumidor de fondo mirara ese `scan_id`) hasta el próximo evento para
/// ese `scan_id` o la próxima limpieza explícita — no se persigue una
/// limpieza inmediata con contadores de referencias adicionales. El coste
/// de una entrada huérfana es un `Sender` vacío en el `HashMap` (unos
/// pocos bytes), acotado por el número de `scan_id` que de verdad han
/// tenido un stream SSE alguna vez.
pub struct RealtimeRegistry {
    channels: RwLock<HashMap<String, broadcast::Sender<ScanOutcomeEvent>>>,
}

impl RealtimeRegistry {
    /// Registro vacío.
    pub fn new() -> Self {
        Self { channels: RwLock::new(HashMap::new()) }
    }

    /// Se suscribe a los eventos de `scan_id`, creando el canal si es la
    /// primera suscripción. Usado por el handler SSE al abrir la conexión.
    pub fn subscribe(&self, scan_id: &str) -> broadcast::Receiver<ScanOutcomeEvent> {
        // Lock de escritura siempre: más simple que un fast-path de
        // lectura + upgrade, y barato dado el volumen esperado (ver nota
        // de diseño del módulo) — no sobre-ingeniería.
        let mut channels = self.channels.write().unwrap_or_else(|p| p.into_inner());
        channels
            .entry(scan_id.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    /// Empuja `event` a cualquier cliente SSE suscrito a
    /// `event.scan_id()` (usa `event.correlation_id`, que ES el `scan_id`
    /// propio de Gateway). Si no hay ningún `Sender` registrado, o el
    /// `Sender` no tiene receivers vivos, el evento simplemente no tiene
    /// destinatario — no se bufferiza (decisión ya tomada por el líder).
    pub fn publish(&self, scan_id: &str, event: ScanOutcomeEvent) {
        let channels = self.channels.read().unwrap_or_else(|p| p.into_inner());
        if let Some(sender) = channels.get(scan_id) {
            // `send` devuelve Err si no hay receivers vivos en ESTE instante:
            // no es un fallo real, es "nadie está escuchando ahora mismo".
            let _ = sender.send(event);
        }
    }

    /// Limpia `scan_id` del registro si su `Sender` ya no tiene ningún
    /// receiver vivo. Se llama best-effort al terminar un stream SSE (no
    /// hay una tarea de limpieza periódica — ver nota de diseño del
    /// módulo).
    pub fn remove_if_orphaned(&self, scan_id: &str) {
        let mut channels = self.channels.write().unwrap_or_else(|p| p.into_inner());
        if let Some(sender) = channels.get(scan_id) {
            if sender.receiver_count() == 0 {
                channels.remove(scan_id);
            }
        }
    }
}

impl Default for RealtimeRegistry {
    fn default() -> Self { Self::new() }
}
```

Notas:
- `broadcast::Sender::receiver_count()` existe en `tokio::sync::broadcast`
  (no hace falta ninguna crate extra) y es la forma estándar de saber si
  "ya no queda nadie escuchando".
- El manejo de lock envenenado (`unwrap_or_else(|p| p.into_inner())`) copia
  literalmente el idioma ya usado en `auth::LoginStateStore` — no un
  `.unwrap()` desnudo, que viola `docs/conventions.md` ("Nada de
  `unwrap()`/`expect()`/`panic!()` fuera de tests").
- `RealtimeRegistry` se añade a `AppState` (en `src/api.rs`) como
  `Arc<RealtimeRegistry>`, igual patrón que `Arc<LoginStateStore>`.

## 3. Cómo el handler SSE sabe cuándo cerrarse

`broadcast::Receiver<T>::recv(&mut self) -> impl Future<Output = Result<T, RecvError>>`,
con `RecvError::{Closed, Lagged(u64)}`. El stream que consume `axum::Sse`
necesita `Stream<Item = Result<Event, Infallible>>` que termine (`None`)
justo después de emitir el evento terminal.

**No hace falta añadir `tokio-stream`** (crate con `BroadcastStream`, no
presente hoy en `Cargo.lock`) si se construye el `Stream` a mano con
`futures_util::stream::unfold`, que además ya conoce este repo (usado en
`tests/scan_submission.rs` vía `futures_util::StreamExt` para consumir un
`lapin::Consumer`). **Ojo**: `futures-util = "0.3"` hoy solo está en
`[dev-dependencies]` — como el `Stream` del handler SSE es código de
`src/`, no de `tests/`, hace falta **moverlo (o añadirlo también) a
`[dependencies]`**. Es la única crate nueva/reubicada que hace falta para
esta feature del lado SSE.

```rust
use std::convert::Infallible;

use axum::response::sse::Event;
use futures_util::stream::{self, Stream};
use tokio::sync::broadcast;

use crate::domain::ScanOutcomeEvent;

fn scan_event_stream(
    receiver: broadcast::Receiver<ScanOutcomeEvent>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(Some(receiver), |state| async move {
        let mut receiver = state?; // `state` es `None` => el stream ya terminó
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let is_terminal = event.is_terminal(); // status == completed | failed
                    let sse_event = Event::default()
                        .json_data(&event)
                        .unwrap_or_else(|_| {
                            // No hay forma sana de fallar un `Stream<Item = Result<_, Infallible>>`;
                            // se degrada a un evento explícito de error en vez de tumbar el stream.
                            Event::default()
                                .event("error")
                                .data("no se pudo serializar el evento de escaneo")
                        });
                    let next_state = if is_terminal { None } else { Some(receiver) };
                    return Some((Ok(sse_event), next_state));
                }
                // Se perdieron eventos intermedios (receiver lento): no es
                // fatal, seguimos escuchando el siguiente.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                // El `Sender` se soltó (scan_id nunca tuvo/ya no tiene
                // productor) → fin ordenado del stream.
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}
```

`stream::unfold` con estado `Option<Receiver>`: al devolver `(item, None)`
como próximo estado, la siguiente llamada al closure hace `state?` sobre
`None` y el `unfold` termina el stream (`Poll::Ready(None)`) — exactamente
"emite el último evento y luego termina", sin quedarse esperando
indefinidamente. El handler debería además llamar a
`registry.remove_if_orphaned(&scan_id)` cuando el stream termina (se puede
envolver con `.chain(stream::once(...))` o, más simple, con un pequeño
wrapper `Drop`/`futures_util::stream::unfold` con un guard — cualquiera de
las dos es una decisión de implementación menor, no bloqueante).

## 4. Patrón para testear un endpoint SSE en un test de integración

Confirmado en el propio repo (`tests/usuarios_profile_proxy.rs`,
`tests/session_middleware_and_me.rs`, `tests/oidc_login.rs`,
`tests/scan_submission.rs`): el patrón real ya usado aquí es servidor real
sobre puerto efímero, **no** `tower::ServiceExt::oneshot` (que no sirve para
leer un body en streaming antes de que termine):

```rust
let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
let addr = listener.local_addr().unwrap();
tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
// reqwest::Client contra http://127.0.0.1:{addr.port()}/...
```

**Gotcha de dependencias, verificado**: `reqwest::Response::bytes_stream()`
está tras `#[cfg(feature = "stream")]` en `reqwest-0.12.28/src/async_impl/response.rs`,
y el `Cargo.toml` de este repo declara
`reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }`
— **`stream` NO está activo hoy**, `bytes_stream()` no compila tal cual.
Recomendación: añadir en `[dev-dependencies]` (no en `[dependencies]`, para
no meter esta feature en el binario de producción):
```toml
reqwest = { version = "0.12", default-features = false, features = ["stream"] }
```
Con `edition = "2021"` (resolver v2, ya fijado en este `Cargo.toml`), Cargo
unifica los features de `reqwest` solo para los targets que enlazan
`dev-dependencies` (tests) — el `cargo build` normal del binario no se ve
afectado.

Parseo manual de `text/event-stream` (formato `data: ...\n\n`, sin crate
adicional — el propio `axum::response::sse` tampoco usa ninguna para el
lado servidor, así que es razonable no añadir una para el lado cliente de
test):

```rust
use futures_util::StreamExt;

/// Lee del stream de bytes hasta completar el próximo evento SSE
/// (`\n\n`) y devuelve la concatenación de sus líneas `data: `, o `None`
/// si el stream terminó sin más eventos.
async fn next_sse_data_field(
    stream: &mut (impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin),
    buffer: &mut String,
) -> Option<String> {
    loop {
        if let Some(pos) = buffer.find("\n\n") {
            let raw_event: String = buffer.drain(..pos + 2).collect();
            let data = raw_event
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:"))
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !data.is_empty() {
                return Some(data);
            }
            continue; // evento sin `data:` (p. ej. un keep-alive/comentario) -> seguir
        }
        match stream.next().await {
            Some(Ok(chunk)) => buffer.push_str(&String::from_utf8_lossy(&chunk)),
            _ => return None,
        }
    }
}
```

Ejemplo concreto de test (boceto — la publicación real hacia
`gateway.scan-outcomes` vía `testcontainers`/`lapin` es la otra mitad de
esta feature, investigada aparte; aquí solo se ilustra el lado SSE,
reusando el helper de publicación de test que produzca el otro agente):

```rust
#[tokio::test]
#[ignore = "requiere Docker"] // por el RabbitMQ real de fondo, no por el lado SSE en sí
async fn sse_stream_relays_scan_outcomes_in_order_and_closes_on_terminal_state() {
    let gateway = spawn_gateway_with_scan_owned_by_session(SCAN_ID).await; // helper de la otra mitad
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/scans/{SCAN_ID}/events", gateway.base_url))
        .header(reqwest::header::COOKIE, gateway.session_cookie_header())
        .send()
        .await
        .expect("la conexión SSE debe aceptarse");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let mut byte_stream = response.bytes_stream();
    let mut buffer = String::new();

    // Publicar started/completed (dos mensajes reales; el esquema de
    // ScanOutcome solo tiene 3 variantes started/completed/failed y un
    // escaneo llega como mucho a UNO de los dos terminales — para probar
    // "3 mensajes en orden" hace falta o bien dos scan_id distintos
    // (aislamiento por scan_id) o repetir `started` antes de `completed`;
    // no hay una variante intermedia "progress" en el contrato real, ver
    // `broker/contracts/scan-outcome.schema.json`).
    let publisher = tokio::spawn(publish_scan_outcomes_to_test_queue(
        SCAN_ID,
        vec!["started", "started", "completed"],
    ));

    for expected_status in ["started", "started", "completed"] {
        let data = tokio::time::timeout(
            Duration::from_secs(5),
            next_sse_data_field(&mut byte_stream, &mut buffer),
        )
        .await
        .expect("no debe colgarse esperando un evento")
        .expect("debe llegar el evento esperado");
        assert!(data.contains(&format!("\"status\":\"{expected_status}\"")));
    }

    // Tras el evento terminal (completed), el stream debe cerrarse
    // ordenadamente: ni un evento de más, ni colgarse.
    let after_terminal = tokio::time::timeout(
        Duration::from_secs(2),
        next_sse_data_field(&mut byte_stream, &mut buffer),
    )
    .await
    .expect("el stream debe cerrarse (None), no colgarse, tras el evento terminal");
    assert!(after_terminal.is_none());

    publisher.await.expect("la tarea de publicación no debe hacer panic");
}
```

Un test que NO necesita Docker (unitario/integración pura de `realtime` +
handler SSE, sin `lapin`/RabbitMQ real) es igual de válido y más rápido para
cubrir "el stream se cierra en estado terminal": construir un
`RealtimeRegistry`, suscribirse, y en paralelo llamar directamente a
`registry.publish(scan_id, ...)` en vez de pasar por una cola real — cubre
el lado `axum`/`realtime` sin depender de Docker, dejando el
`#[ignore = "requiere Docker"]` solo para el/los tests que de verdad
ejercen `lapin` end-to-end (coherente con `docs/conventions.md`: "Todo test
que dependa de Docker vía `testcontainers` se marca `#[ignore...]`" — un
test que no toca Docker no debería llevar esa marca innecesariamente).

## 5. Middleware de sesión sobre la ruta SSE

Sin peculiaridades: `axum::middleware::from_fn_with_state` (como ya usa
`auth::require_session`) envuelve `Next::run(request).await -> Response`
igual sea el handler interno una respuesta normal o un `Sse<...>` — el
`Body` de axum 0.7 (`axum_core::body::Body`) ya es streaming por dentro
(basado en `http_body::Body`/`Frame`) para *cualquier* respuesta, así que
"ruta de streaming" no es un caso especial para el middleware: solo ve un
`Response` antes de que su cuerpo se drene hacia el socket.

Aplicación concreta: añadir la ruta a `protected_router()` en `src/api.rs`
junto a `/api/me`/`/api/profile`/`/api/scans`, bajo el mismo
`.layer(middleware::from_fn_with_state(validator, auth::require_session))`,
y añadir su entrada a `ROUTES` (`protected: true`) para no romper el test
de enumeración de rutas de `session_middleware_and_me`.

**Gotcha real encontrado, no de middleware sino de sintaxis de ruta**:
axum 0.7 usa matchit 0.7, con sintaxis de parámetro `:nombre` (`*nombre`
para wildcard) — la sintaxis `{nombre}` (la que usa el enunciado de esta
tarea, y la que usa OpenAPI) es de **axum 0.8** (`CHANGELOG.md` de
`axum-0.8.9`: "Upgrade matchit to 0.8, changing the path parameter syntax
from `/:single` ... to `/{single}`"). Con `axum = "0.7"` fijado en este
repo, la ruta debe registrarse como:
```rust
.route("/api/scans/:scan_id/events", get(scan_events))
```
usando `axum::extract::Path<String>` para extraer `scan_id` — `{scan_id}`
en axum 0.7 no produce un parámetro de ruta (no hay validación que lo
rechace en tiempo de arranque; simplemente no matchea nada real). Vale la
pena que el implementer lo tenga presente: es el error más fácil de cometer
al copiar el path literal `GET /api/scans/{scan_id}/events` del enunciado
de la feature a `Router::route`.

## Resumen de cambios a `Cargo.toml` recomendados (ninguno para producción salvo uno)

| Crate | Dónde | Motivo |
|---|---|---|
| `futures-util` | mover/añadir a `[dependencies]` (hoy solo en `[dev-dependencies]`) | `stream::unfold` para construir el `Stream<Item = Result<Event, Infallible>>` en `src/realtime.rs`/`src/api.rs` — es código de producción, no de test |
| `tokio` | añadir `"sync"` explícito a `features = [...]` | hoy compila por activación transitiva (confirmado con `cargo tree -e features -i tokio`); hacerlo explícito evita que un cambio en otra dependencia rompa la build en silencio |
| `reqwest` | añadir entrada en `[dev-dependencies]` con `features = ["stream"]` | `Response::bytes_stream()` está tras ese feature gate y hoy no está activo; sin tocar `[dependencies]` para no afectar el binario |

No se recomienda añadir `dashmap` ni `tokio-stream` (ver §2 y §3) — ambas
opciones evaluadas y descartadas por sobre-ingeniería frente al volumen
esperado y a las crates ya presentes en el árbol de dependencias.
