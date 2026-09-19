# Implementación: feature 6 — `scan_submission`

> Informe del `implementer`. El `reviewer` debe leer esto antes de emitir
> veredicto; no se pega el diff completo aquí, solo decisiones y
> verificación.

## Archivos creados/modificados

- `Cargo.toml` — nuevas dependencias de producción: `tokio-executor-trait`,
  `tokio-reactor-trait` (runtime de `lapin` sobre `tokio`), `async-trait`
  (trait `ScanRequestPublisher` con método `async fn` usable como `dyn`),
  `uuid` (generación del `scanId`). Nuevas dev-dependencies: `rustls`
  (instalación defensiva del backend criptográfico antes de la primera
  conexión AMQPS en tests), `futures-util` (`.next()` sobre el `Consumer` de
  `lapin` en el test de integración).
- `src/domain.rs` — `ScanSubmission`/`ScanSubmissionError`: validación pura
  de IP/CIDR (RF-02/RF-03), con tests unitarios (camino feliz IPv4/IPv6,
  CIDR IPv4/IPv6, trim de espacios; caminos de error: vacío, no-IP,
  prefijo CIDR fuera de rango, prefijo no numérico).
- `src/broker.rs` — reemplazo completo del stub vacío: `ScanRequest` (shape
  copiado literal de `broker/contracts/scan-request.schema.json`, `Debug`
  manual que redacta `ssh_credentials_ref`), `BrokerError` (`thiserror`),
  trait `ScanRequestPublisher` (`async_trait`, para inyección de
  dependencias en `AppState`), `BrokerPublisher` (conexión+canal AMQPS
  persistentes vía `lapin` 2.5.5, `confirm_select` activado una vez,
  `connect`/`connect_with_ca_pem`), `build_amqps_uri` (helper puro, testeado
  unitariamente). Tests unitarios: construcción de URI, redacción en
  `Debug`, shape exacto de la serialización JSON (6 claves, sin extra).
- `src/usuarios_client.rs` — `ScanStatus` (enum confirmado contra
  `user-service/src/domain.rs`, `SCREAMING_SNAKE_CASE`), `ScanHistoryEntry`
  (contrato real de `POST /users/me/scans`), `ScanTargetCredentials`
  (contrato **especulativo** de `GET /users/me/scan-targets`, `Debug`
  manual que redacta `ssh_credentials_ref`), 2 nuevas variantes de
  `UsuariosClientError` (`ScanTargetResolutionNotImplemented`,
  `ScanTargetNotConfigured`), 3 métodos nuevos
  (`create_scan_history`, `update_scan_status`, `resolve_scan_target`),
  refactor de `send_and_decode` a genérico (`<T: DeserializeOwned>`, antes
  atado a `UserProfile`) para reutilizarlo también con `ScanHistoryEntry`.
  Tests unitarios: nuevas URLs, serialización `ScanStatus`, deserialización
  del contrato real, redacción en `Debug`, mensajes de error sin URL base.
- `src/api.rs` — `AppState.broker_publisher: Arc<dyn ScanRequestPublisher>`;
  `POST /api/scans` (handler `submit_scan`, protegido, añadido a `ROUTES` y
  a `protected_router`); `ScanSubmissionRequest`/`ScanSubmissionResponse`;
  `ScanSubmitError` (agrega `ScanSubmissionError`/`UsuariosClientError`/
  `BrokerError` con su propio `IntoResponse`); extensión del
  `IntoResponse for UsuariosClientError` ya existente con los 2 status
  nuevos (`501`/`422`).
- `tests/scan_submission.rs` (nuevo) — 4 tests: 2 sin Docker (target
  inválido → 400 sin llamadas externas; API de resolución de credenciales
  ausente → 501) + 1 sin Docker adicional (API presente pero sin
  credenciales configuradas → 422) + 1 `#[ignore = "requiere Docker"]`
  (camino feliz contra RabbitMQ real vía `testcontainers`, publica y
  verifica el `ScanRequest` en una cola de test bindeada a
  `scan.requests`/`scan.request`, declarada con el usuario `lab-admin`).
- `tests/oidc_login.rs`, `tests/session_middleware_and_me.rs`,
  `tests/usuarios_profile_proxy.rs` — actualizados mecánicamente para el
  nuevo campo `AppState.broker_publisher`, inyectando un doble de prueba
  (`NeverPublishesToBroker`) que hace `panic!` si se invoca (nunca deben
  llegar a publicar en el Broker, esas features no ejercen `POST
  /api/scans`).
- `rabbitmq/definitions.json`, `rabbitmq/rabbitmq.conf`,
  `rabbitmq/tls/{ca_certificate,server_certificate,server_key}.pem`
  (nuevos) — copia **literal** de `broker/rabbitmq/` (no se copió
  `ca_key.pem`: no lo usa ni el servidor RabbitMQ de test ni el cliente,
  solo se usó en su momento para firmar `server_certificate.pem`).

## Decisiones de diseño

### 1. Dos identificadores distintos para un mismo escaneo (tensión documentada, no inventada)

El criterio de aceptación #2 exige generar el `scanId`/`correlation_id`
**antes de cualquier llamada externa**. Pero el contrato real y confirmado
de `user-service` (`POST /users/me/scans`, `CreateScanRequest { target }`)
**no acepta un `scan_id` externo**: lo asigna `ms-usuarios` internamente
(`Uuid::new_v4()` del lado de `user-service`). No podía forzar que ambos
sistemas usaran el mismo valor sin inventar una API que no existe.

Resolución adoptada: `submit_scan` genera su propio `scan_id` (UUID v4) tan
pronto pasa la validación de formato, **antes** de tocar `ms-usuarios`. Ese
valor es el que se usa como `correlation_id` del `ScanRequest` publicado en
el Broker y el que se devuelve al cliente como `scanId`. El `scan_id` que
devuelve `ms-usuarios` en `ScanHistoryEntry` (distinto) se guarda solo
internamente, para la llamada de compensación `update_scan_status` si el
publish al Broker falla. Documentado con un doc-comment explícito en
`UsuariosClient::create_scan_history`.

**Nota para el reviewer/features futuras**: esto implica que la feature
`scan_outcome_relay` (consumo de `gateway.scan-outcomes`, que trae
`correlation_id` = el `scan_id` propio de Gateway) necesitará su propio
mecanismo para mapear ese `correlation_id` al `scan_id` real de
`ms-usuarios` al actualizar el histórico — no puede asumir que son el mismo
valor. Es una consecuencia directa de la tensión entre el criterio de
aceptación (literal, no reinterpretado) y el contrato real de
`user-service` (tampoco inventado), no una elección arbitraria.

### 2. Endpoint especulativo para resolver `network_user`/`ssh_credentials_ref`/`has_sudo`

`GET /users/me/scan-targets?target=<ip-o-cidr>` (query param, no path
segment, porque un rango CIDR contiene `/` y complicaría el path). Devuelve
`{"network_user", "ssh_credentials_ref", "has_sudo"}`. Documentado como
especulativo en el doc-comment del módulo `usuarios_client` y en
`UsuariosClient::resolve_scan_target` — nunca se trata como contrato
confirmado. Un `404` real de `ms-usuarios` hoy (la ruta no existe) se
traduce a `UsuariosClientError::ScanTargetResolutionNotImplemented` → `501`;
un `422` (hipotético, cuando la API exista pero falten credenciales) → `422`
vía `ScanTargetNotConfigured`. Ambos casos están cubiertos por tests de
integración rápidos (sin Docker).

### 3. `lapin` 2.5.5, confirms síncronos, sin reconexión automática

Seguido al pie de la letra lo verificado en
`progress/explore_lapin_publish.md`: `Connection::connect_with_config` +
`OwnedTLSConfig`, executor/reactor `tokio` explícitos
(`tokio-executor-trait`/`tokio-reactor-trait`), `confirm_select` una sola
vez al conectar (no por publish), y **sí se espera el ack/nack real** del
Broker en el hot path de `POST /api/scans` (no solo el envío del frame) —
trade-off documentado en `src/broker.rs`: RNF-04 exige <500ms, no
"instantáneo", y un ack en la misma subred privada añade típicamente un
solo dígito de milisegundos; es lo único que permite distinguir "se
publicó" de "se envió el frame pero el Broker lo rechazó", que es
justamente lo que el criterio de aceptación #6 exige poder detectar para
marcar `Fallido`. No se implementó reconexión automática (`lapin` 2.5.5 no
la trae de fábrica): un canal muerto se reporta como `BrokerError` igual
que cualquier otro fallo de publish, consistente con el alcance de esta
feature (detectar y reportar, no recuperarse).

### 4. `AppState.broker_publisher` como `Arc<dyn ScanRequestPublisher>`

Para que los tests de las features 3/4/5 (que construyen un `AppState`
completo pero nunca ejercen `POST /api/scans`) no necesiten una conexión
AMQPS real. Mismo patrón de inyección que ya usa este repo para
`usuarios_client`/`oidc_client`. Requirió `async-trait` (no hay soporte
nativo estable para `async fn` en un trait usado como `dyn` sin él).

### 5. `is_connected()` en `BrokerPublisher`

El campo `connection: lapin::Connection` se mantiene en el struct
únicamente para no destruir la conexión mientras el `Channel` la necesite
(un `Channel` deja de funcionar si su `Connection` se destruye). Para que
ese campo no dispare `dead_code` bajo `-D warnings`, se expone
`is_connected()` (lee `connection.status().connected()`), que además es una
capacidad legítima (diagnóstico de salud), no un mero placeholder.

## Verificación de cada criterio de aceptación

1. **400 sin tocar `ms-usuarios` ni el Broker con IP/CIDR inválido** —
   `ScanSubmission::parse` corre antes de cualquier `.await` externo en
   `submit_scan`; test
   `scan_submission_rejects_invalid_target_without_touching_ms_usuarios_or_broker`
   apunta `ms_usuarios_base_url` a un puerto sin nada escuchando y
   `broker_publisher` a un doble que hace `panic!` si se invoca — ambos
   pasan, confirmando que ninguno se tocó.
2. **`scanId`/`correlation_id` propio antes de cualquier llamada externa** —
   `uuid::Uuid::new_v4()` se genera inmediatamente después de la
   validación, antes de `resolve_scan_target`. Ver decisión de diseño #1
   para la tensión documentada con el contrato real de `ms-usuarios`.
3. **Error explícito 501/422 si la API de credenciales no existe/no hay
   configuración** — cubierto por 2 tests de integración (sin Docker):
   `scan_submission_returns_an_explicit_error_when_ms_usuarios_scan_target_api_is_unavailable`
   (404 real → 501) y
   `scan_submission_returns_an_explicit_error_when_ms_usuarios_has_no_credentials_configured`
   (422 → 422).
4. **Histórico + publicación en el Broker cuando los 3 campos se
   resuelven** — cubierto por el test `#[ignore = "requiere Docker"]`
   (camino feliz): la cola de verificación recibe un `ScanRequest` con
   exactamente las 6 claves del schema, sin campos extra.
5. **Respuesta HTTP tan pronto se confirma histórico + publicación, sin
   esperar desenlace** — el handler no suscribe ni espera ningún consumo de
   `gateway.scan-outcomes` (eso es la feature 7, no tocada); responde
   inmediatamente tras el `await` de `publish_scan_request`.
6. **Fallo de publicación tras histórico registrado → marca `Fallido` +
   reporta error, nunca `Pendiente` huérfano** — implementado en
   `submit_scan`: si `publish_scan_request` falla, se llama a
   `update_scan_status(..., ScanStatus::Fallido)` (best-effort: un fallo de
   esa llamada se loggea y no oculta el error original) antes de devolver
   el error al cliente. No hay un test de integración específico para esta
   rama (requeriría poder forzar un fallo de publish tras un histórico ya
   registrado, p. ej. derribando el canal a mitad de camino) — cubierto
   solo a nivel de código/lectura, marcado aquí como limitación conocida
   para que el reviewer lo evalúe explícitamente.
7. **Tests de integración** — los 4 descritos arriba; 3 corren en `cargo
   test` normal (no dependen de Docker) y 1 en `cargo test -- --ignored`
   (`#[ignore = "requiere Docker"]`), ejecutado contra un `rabbitmq:4.3.5-management`
   real con la topología copiada literal de `broker/rabbitmq/definitions.json`.

## Resultado de los comandos de verificación

- `cargo build` — compila sin warnings.
- `cargo clippy --all-targets -- -D warnings` — sin advertencias.
- `cargo fmt --check` — sin diferencias.
- `cargo test` (sin `--ignored`) — 38 tests unitarios + todos los de
  `tests/` en verde (incluye los 3 nuevos de `scan_submission` que no
  requieren Docker).
- `cargo test -- --ignored` — el test de camino feliz contra RabbitMQ real
  pasa (Docker estaba disponible en este entorno). Sin contenedores
  huérfanos tras la corrida (`docker ps -a` verificado).
- `./init.sh` — `[OK] Entorno listo` de punta a punta, incluida la sección
  de tests con Docker.

## Dudas / puntos para el reviewer

- La tensión entre los dos identificadores (`scanId` propio de Gateway vs.
  `scan_id` de `ms-usuarios`) descrita en la decisión #1: confirmar que es
  aceptable dejarla documentada para la feature `scan_outcome_relay`, en vez
  de intentar resolverla aquí inventando una API de `user-service` que no
  existe.
- El endpoint especulativo `GET /users/me/scan-targets` (path y shape) es
  una suposición de este repo, igual que ya se hizo en la feature 5 con el
  perfil — a confirmar cuando `user-service` implemente esa API de verdad.
- No hay test de integración específico para la rama "publish falla
  después de histórico ya registrado" (criterio #6): validado solo por
  lectura del código. Si el reviewer lo considera necesario, se podría
  forzar cerrando el canal AMQPS entre el registro de histórico y el
  publish (requeriría exponer un hook de test adicional en
  `BrokerPublisher`, no trivial sin tocar su API pública).
