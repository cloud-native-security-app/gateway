# Decisiones técnicas

Registro breve de decisiones (formato ADR) destiladas del historial de
desarrollo del repo. Cada entrada: contexto, decisión y consecuencia. Las
decisiones de arquitectura de alto nivel viven en `docs/architecture.md` y los
límites de seguridad en `docs/security-scope.md`; aquí solo se registran las
que no son evidentes leyendo el código.

## D-01 — `openidconnect` con rustls y issuer configurable

- **Contexto:** el login OIDC debe probarse sin tocar Google real.
- **Decisión:** `openidconnect = "4"` con sus features por defecto (ya trae
  `reqwest` + `rustls`, nunca `native-tls`, coherente con `lapin`). El issuer
  se lee de `GOOGLE_OIDC_ISSUER_URL` (por defecto `https://accounts.google.com`)
  y se usa discovery.
- **Consecuencia:** los tests apuntan a un IdP de prueba (servidor `axum`
  efímero con JWKS RSA propio, sin `wiremock`). La crate **no** valida `state`
  (CSRF): lo valida el handler; `nonce`, firma, `aud`, `iss` y `exp` sí.

## D-02 — Sesión propia: JWT en cookie, con versiones acotadas

- **Decisión:** `jsonwebtoken` 11 (`rust_crypto`) y `axum-extra = "0.9.6"`,
  porque `axum-extra` 0.12 exige `axum` 0.8 y este repo está en `axum` 0.7.
- **Consecuencia:** subir `axum` implica subir `axum-extra` a la vez.

## D-03 — `lapin` 2.x con executor de `tokio` y conexión persistente

> Reemplazada por D-15 (SNS + SQS); se conserva como historial.

- **Contexto:** `broker/` usa `lapin` 4; la API de conexión difiere de la 2.5.
- **Decisión:** `lapin = "2"` (`rustls`, sin features por defecto) más
  `tokio-executor-trait`/`tokio-reactor-trait` para correr sobre el runtime de
  `axum` en vez del pool propio de `lapin`. Una conexión y canal persistentes
  (con `confirm_select`) compartidos en `AppState`, no una conexión por request.
- **Consecuencia:** en producción TLS se verifica contra el almacén de
  certificados del sistema (`connect`); una CA de laboratorio solo se inyecta
  vía `connect_with_ca_pem` (tests). No hace falta declarar exchanges/colas:
  los crea la topología del Broker.

## D-04 — Publicación: confirms y presupuesto de 500 ms

> Reemplazada por D-15: el equivalente de los confirms es el `MessageId` de SNS.

- **Decisión:** el canal activa `confirm_select` una vez y
  `publish_scan_request` espera el ack real del Broker (no solo el envío del
  frame); el costo es de pocos ms dentro de la subred privada, muy por debajo
  de RNF-04 (< 500 ms). Los errores de publicación se mapean a un `BrokerError` tipado (`thiserror`) que no expone la URL ni la
  credencial AMQPS en su `Display`.

## D-05 — Consumo: mensaje malformado se descarta sin requeue

> Reemplazada por D-15: los malformados se reenvían a la DLQ y se borran.

- **Decisión:** un `ScanOutcome` que no deserializa se rechaza con
  `reject`/`nack(requeue = false)`, no `ack` (perdería el rastro) ni requeue
  (bucle infinito; el contador `x-delivery-limit` solo avanza con `reject`).
  El log registra el error de deserialización, nunca el payload completo.

## D-06 — Relay SSE por `scan_id`

- **Decisión:** `axum::response::sse` sin `tokio-stream` (basta
  `futures-util::stream::unfold`); registro de suscriptores por `scan_id` en
  `realtime`. El stream se cierra al llegar un resultado terminal.
- **Consecuencia:** los tests SSE necesitan `reqwest` con la feature `stream`
  (solo `dev-dependencies`). Atención a la sintaxis de ruta `{scan_id}` de `axum`.

## D-07 — Tests de integración con Docker real y AMQPS

> Reemplazada por D-15: los tests usan LocalStack; se conserva la regla de `#[ignore = "requiere Docker"]`.

- **Decisión:** `testcontainers` 0.20 (`GenericImage`, sin
  `testcontainers-modules`) levanta `rabbitmq:*-management` con la topología
  copiada literal de `broker/rabbitmq/definitions.json`. Los tests usan AMQPS
  (5671) porque el `rabbitmq.conf` de `broker/` exige TLS siempre. Se instala
  explícitamente el proveedor criptográfico de `rustls` antes de conectar para
  evitar el conflicto de doble proveedor. Los tests con Docker llevan
  `#[ignore = "requiere Docker"]`.

## D-08 — CORS y redirect post-login con URL fija

- **Contexto:** `front` y `gateway` están en orígenes distintos.
- **Decisión:** `GET /auth/callback` redirige (302) a `FRONT_BASE_URL`, nunca a
  un valor derivado de la request (evita open redirect). La `CorsLayer` usa el
  origen (`scheme://host[:puerto]`) derivado de `FRONT_BASE_URL`, con
  credenciales, porque `Origin` nunca lleva `path`.

## D-09 — Logout robusto detrás de ALB/proxy

- **Contexto:** en AWS el logout devolvía 204 y la sesión seguía activa.
- **Causa:** (1) `CookieJar::remove` solo emite `Set-Cookie` si la request trae
  la cookie; (2) respuestas sin `Cache-Control` podían servirse cacheadas;
  añadir `Secure` a la cookie de borrado no era la causa.
- **Decisión:** el logout siempre emite la cookie expirada con los mismos
  atributos (`Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`), más
  `Clear-Site-Data` y `Cache-Control: no-store`.

## D-10 — El perfil se crea durante el login

- **Contexto:** `network_credentials.user_id` referencia `users(user_id)` en
  `ms-usuarios`, y esa fila solo la crea `PUT /users/me`; sin ella,
  `POST /api/network-credentials` respondía 502.
- **Decisión:** el callback OIDC llama a `upsert_profile` tras validar el ID
  token. Gateway también expone el proxy hacia las credenciales de red de
  `ms-usuarios` (front nunca habla directo con ese servicio, RNF-03).

## D-11 — Reconexión al Broker (publicador y consumidor)

> Reemplazada por D-15: el SDK de AWS no mantiene conexiones persistentes; el consumidor reintenta con backoff.

- **Contexto:** incidentes en AWS: al reiniciarse RabbitMQ, todo
  `POST /api/scans` daba 502 hasta reiniciar gateway, y el relay SSE moría en
  silencio mientras `/health` seguía sano. `lapin` 2.5 no reconecta solo.
- **Decisión:** el publicador detecta conexión caída y reconecta bajo `RwLock`;
  el consumidor reconecta con backoff exponencial y pocos intentos acotados. El
  `lapin::Error` original se conserva como `#[source]` y se loguea con `Debug`
  sin filtrar credenciales.

## D-12 — Rate limiting por usuario

- **Decisión:** limitador en memoria propio (ventana por usuario, sin
  `tower_governor`) sobre `POST /api/scans`, con clave = identidad de la
  sesión (no IP), configurable por `SCAN_SUBMISSION_RATE_LIMIT_*`.

## D-13 — OpenAPI generado, sin UI

- **Decisión:** `utoipa` genera la especificación desde los handlers y se sirve
  en `GET /api/openapi.json`; no se añade una UI de Swagger.

## D-14 — Imagen Docker

- **Decisión:** build multi-stage (`rust:1.98-bookworm` a `distroless/cc:nonroot`),
  bases fijadas por tag y digest para builds reproducibles. Los CA del sistema de
  la imagen base cubren el TLS saliente hacia Google, `ms-usuarios` y el Broker
  (desde D-15, los endpoints HTTPS de SNS/SQS).

## D-15 — SNS + SQS reemplazan a RabbitMQ/`lapin`

- **Contexto:** Amazon MQ no está disponible en el Learner Lab y se eligió
  mensajería gestionada (SNS + SQS). Reemplaza a D-03, D-04, D-05, D-07 y D-11
  (se conservan como historial). Fecha: 2026-10-17; consumo con borrado tras
  `handle`: 2026-10-19.
- **Decisión:**
  - Publicar con `aws-sdk-sns` en dos topics; la antigua routing key viaja como
    atributo de mensaje `String` `routing_key` (`scan.request`,
    `scan.cancellation`) y los cuerpos JSON no cambian. Un `Publish` exitoso
    (devuelve `MessageId`) es el equivalente del confirm de D-04.
  - Consumir con `aws-sdk-sqs` (long polling de 20 s). El mensaje se borra
    **después** de que `ScanOutcomeHandler::handle` retorna (entrega al menos
    una vez): un crash a mitad lo reentrega y, tras 3 recepciones, la
    `RedrivePolicy` lo manda a la DLQ. El handler tolera duplicados (repite el
    evento SSE y reaplica el mismo estado en `ms-usuarios`).
  - Un mensaje malformado se reenvía a la DLQ (conservando `routing_key`) y se
    borra de la cola; es el equivalente de `nack(requeue = false)` de D-05.
  - Errores de recepción: backoff exponencial 1-30 s sin salir del bucle;
    reemplaza a los intentos acotados de D-11. El SDK no mantiene conexiones
    persistentes, así que no hay reconexión que gestionar.
  - Shutdown ordenado en `gateway::run`: `SIGTERM`/`Ctrl-C` cancelan un
    `CancellationToken`, axum drena (máx. 10 s) y se espera al consumidor
    (máx. 10 s) antes de abortarlo.
  - Credenciales de AWS solo por la cadena por defecto (rol de la tarea ECS);
    `AWS_ENDPOINT_URL` solo para LocalStack. Se eliminan `BROKER_AMQPS_URL`,
    `BROKER_VHOST`, `lapin`, `tokio-executor-trait`, `tokio-reactor-trait`, la
    CA/certificados de laboratorio y el directorio `rabbitmq/`.
  - Tests de integración con `localstack/localstack:4.4` vía `testcontainers`
    (arnés en `tests/common/mod.rs`), sin mocks del SDK.
- **Consecuencia:** el contrato de mensajes y los puertos
  (`ScanRequestPublisher`, `ScanOutcomeHandler`) no cambian. La topología
  (topics, colas, suscripciones raw, DLQ) la provee `broker`/Terraform; este
  repo no la declara.

## D-16 — Reporte de escaneo y estado `CANCELADO`

- **Contexto:** `front` necesita el resultado de un escaneo terminado y el
  motivo de un fallo o cancelación; `ms-usuarios` los almacena
  (`user-service`, feature `scan-report`, opción A). Fecha: 2026-10-20.
- **Decisión:**
  - El relay de resultados envía en el mismo `PATCH /scans/{id}` el
    `ScanResult` completo con `COMPLETADO` y el motivo con `FALLIDO`/`CANCELADO`.
    Un motivo vacío se reemplaza por un texto fijo y uno largo se recorta a 500
    caracteres (si no, `ms-usuarios` respondería `400` y el escaneo no llegaría
    a un estado terminal); un `413` por resultado demasiado grande degrada a
    `COMPLETADO` sin reporte.
  - `CANCELADO` se decide por una marca en memoria
    (`ScanOwnershipRegistry::mark_cancel_requested`) puesta cuando
    `POST /api/scans/{id}/cancel` fue aceptado por el Broker; si llega `failed`
    para ese escaneo se envía `CANCELADO`. No se interpreta el texto del motivo
    de `ms-nmap`. **Limitación aceptada:** la marca se pierde al reiniciar el
    Gateway (el escaneo queda `FALLIDO` con el motivo de cancelación de
    `ms-nmap`).
  - `GET /api/scans/{scan_id}/report` traduce el `scanId` del Gateway al de
    `ms-usuarios` con `ScanOwnershipRegistry`, que sigue siendo en memoria: tras
    un reinicio responde `404` aunque el reporte exista.
  - El shape SSE no cambia; desde D-21 el navegador recibe `cancelled` en lugar de `failed` tras una cancelación pedida.

## D-17 — Puerto y protocolo opcionales en `VulnFinding` y `finding.critical`

- **Decisión:** `VulnFinding` acepta y relaya `port` (`u16`) y `protocol`
  opcionales, que se omiten al serializar si faltan (un `null` explícito se
  decodifica igual que la ausencia). En el feed de administración,
  `CriticalFinding.port`/`protocol` son nullable y `event_contract` acepta
  `null` en `finding.critical` (hallazgo a nivel de host). Contrato:
  `broker/contracts/` (D-15 del broker).
- **Consecuencia:** `VulnFinding` conserva `deny_unknown_fields`, por lo que el
  orden de despliegue es Gateway primero y luego `nmap-service`; de lo
  contrario un `completed` con puerto iría a la DLQ. Un hallazgo a nivel de
  host ya no se descarta del feed por tener `port: null`.

## D-18 — Modo `network` de `POST /api/scans` (NS-03)

- **Decisión:** `POST /api/scans` acepta `mode` (`ssh` por defecto, `network`).
  En `network`: (1) el permiso `network_scan` se re-valida contra `ms-usuarios`
  (`GET /users/me`, `can_network_scan`) en cada solicitud, antes de cualquier
  otro trabajo del modo, con la política fail closed de `require_admin`
  (`404`/falso => `403`; error => `503`); no hay claim en el JWT ni caché, así
  que revocar el permiso surte efecto en la siguiente solicitud; (2) denylist
  fija y allowlist opcional (`NETWORK_SCAN_ALLOWED_CIDRS`) en
  `src/network_scan.rs` (loopback, link-local, unique-local `fc00::/7` que
  cubre el metadata IPv6 de AWS `fd00:ec2::254`, multicast, broadcast, sin
  especificar), evaluadas sobre una única forma canónica de la IP (IPv4-mapped
  e IPv4-compatible se tratan como su IPv4 y se publican así; `::` y `::1`
  siguen siendo IPv6), con la denylist primero e inanulable; (3) no se resuelven credenciales SSH y el `ScanRequest` lleva
  `scan_mode: "network"` sin campos de credenciales (el schema del Broker los
  prohíbe). En `ssh` el payload es byte-idéntico al anterior (el campo se omite).
- **`/api/me`:** expone `can_network_scan` leyéndolo de `ms-usuarios` en cada
  llamada (un cambio del permiso se ve sin volver a iniciar sesión); si
  `ms-usuarios` falla, responde `false` en vez de tumbar la ruta.
- **Modo en el histórico:** `GET /api/scans` devuelve `mode` por entrada. En
  NS-03 salía solo de `ScanOwnershipRegistry` (memoria) y se perdía al reiniciar;
  NS-08 lo persiste en `user-service` (ver D-19).

## D-19 — `scan_mode` persistido en el histórico (NS-08)

- **Decisión:** el Gateway envía `scan_mode` (`"network"`) en `POST /users/me/scans`
  (en `ssh` se omite: el cuerpo no cambia y `user-service` asume `ssh`).
  `GET /api/scans` toma `mode` de `scan_mode` del histórico; solo si falta
  (`user-service` anterior) usa `ScanOwnershipRegistry`, y si tampoco, lo omite.
  `scanId` sigue siendo solo memoria. Requiere desplegar `user-service` con la
  columna antes que el Gateway (si no, un `scan_mode` desconocido se ignora y el
  modo `network` vuelve a depender de la memoria).

## D-20 — Objetivo `network` por nombre de host o URL (UT-03)

- **Decisión:** en modo `network`, `target` puede ser una IP, un nombre de host
  RFC 1123 o una URL `http`/`https` (`src/network_target.rs`). El Gateway
  resuelve el nombre (`tokio::net::lookup_host` con timeout, tras el puerto
  `HostResolver`), canonicaliza y evalúa **todas** las direcciones con la
  política existente, y publica una sola IP fijada (primera IPv4 en el orden del
  resolvedor, si no la primera IPv6) como `ip`. Cualquier dirección rechazada
  rechaza el nombre (`422` `target_resolves_to_denied`); sin direcciones, error
  o timeout es `422` `target_unresolvable`.
- **Anti DNS rebinding:** `ms-nmap` nunca resuelve el nombre; escanea la IP que
  el Gateway evaluó, así que no hay una segunda resolución que pueda devolver
  una dirección distinta de la validada. `target_host` viaja solo para mostrar y
  como host HTTP virtual; el patrón RFC 1123 del contrato también deja fuera un
  `-` inicial del argv de nmap.
- **`extra_port`:** se envía solo si la URL trae un puerto explícito distinto de
  80 y 443, ya incluidos en el conjunto por defecto de nmap; un nombre o URL sin
  puerto no lo lleva. Un puerto `0` es `400`.
- **Orden:** el permiso `network_scan` se valida antes de parsear o resolver, así
  que quien no lo tiene no provoca consultas DNS. Credenciales en la URL (`user@`)
  son `400` y el error nunca repite el valor recibido.
- **Histórico y eventos:** el histórico guarda el nombre tal como se escribió
  (minúsculas, sin esquema ni ruta) o la IP; `scan.requested` mantiene
  `target` = IP fijada y añade `target_host`.
- **Aceptado, sin cambio:** la denylist no bloquea RFC 1918 (el objetivo del
  laboratorio es una dirección privada de VPC), así que un nombre que resuelve a
  una IP privada se permite igual que escribir esa IP.

## D-21 — SSE resiliente: keep-alive, reenvío del último evento y `cancelled` (SC-01)

- **Problema (lab):** el ALB cerraba el stream tras 60 s sin bytes; al
  reconectar, un evento terminal publicado durante el corte se perdía (el
  registro lo descartaba sin receptores) y la página quedaba cargando; una
  cancelación llegaba como `failed`.
- **Decisión:**
  - `GET /api/scans/{id}/events` envía un comentario SSE (`: ...`) cada 15 s
    (`KEEP_ALIVE_INTERVAL`); `EventSource` lo ignora.
  - `RealtimeRegistry` recuerda el último evento de cada `scan_id` aunque nadie
    escuche. Un suscriptor nuevo recibe primero ese evento y luego los vivos; si
    es terminal, lo recibe y el stream se cierra. Un `Mutex` único protege
    canales y caché, y publicar y "leer último + suscribirse" son atómicos: no se
    pierde ni se duplica ningún evento. Un duplicado `started` posterior a un
    terminal no lo sobrescribe.
  - **Cotas:** 1024 scans recordados (se descarta el más antiguo) y los
    terminales expiran a los 15 min (purga al publicar y al suscribirse); los no
    terminales solo tienen el tope de tamaño. Ambos valores son parámetros de
    `RealtimeRegistry::with_limits`.
  - `failed` con cancelación pedida (`mark_cancel_requested`) llega al
    navegador como `cancelled` (`ScanLiveEvent`, mismo JSON, conserva `reason`).
    El contrato del Broker y lo enviado a `ms-usuarios` (`CANCELADO`) no cambian.
- **Limitaciones aceptadas:** todo vive en memoria (tras un reinicio no hay
  reenvío ni marca de cancelación; el front debe consultar el histórico); un
  `scan_id` sin evento recordado queda abierto sin emitir nada.
- **Compatibilidad:** el shape no cambia; solo hay un valor de `status` más.

## D-22 — Estado del correo del reporte en el histórico (EM-03)

- **Decisión:** `GET /api/scans` añade `email_status` (`pending`, `sent`,
  `failed`, `disabled`) y `emailed_at` (RFC 3339, solo con `sent`), derivados de
  `report_email_status`/`report_emailed_at` de `user-service`. Los campos son
  aditivos y se omiten cuando no aplican. No se expone el destinatario.
- **Mapeo:** escaneo no `COMPLETADO` -> ambos ausentes. `COMPLETADO` con estado
  `null` o ausente (envío aún no reclamado, o `user-service` anterior) ->
  `pending`. Estado desconocido -> `pending` (nunca `sent`, nunca falla el
  histórico: el cliente lo lee como `String`).
- **Reporte:** `GET /api/scans/{scan_id}/report` no cambia; devuelve el
  `ScanResult` almacenado, sin estado de correo.

## D-23 — SIEM alert ingestion route (SR-02)

- **Route:** `POST /api/integrations/siem/alerts`, one Wazuh alert per request
  (the shape `integratord` hands to a custom integration). It maps `rule.id`,
  `rule.level`, `rule.description`, `agent.id`/`agent.name`, `data.srcip`|`src_ip`,
  `data.dstip`|`dest_ip` and `data.alert.signature` (Suricata via Wazuh) to the
  `siem.alert` payload of broker D-18 and publishes it with `source` `wazuh`
  and partition key `agent.id`. The raw log line is never forwarded.
- **Off by default, mounted only with `SIEM_INGEST_TOKEN`:** without a token
  the route is not in the router, so it is exactly as (non-)existent as any
  other unknown path. In this gateway that is not a bare `404`: the session
  layer is the catch-all, so unknown paths answer `401` without a session.
  The route copies that behavior instead of special-casing a `404`.
- **Machine-to-machine:** it sits outside `require_session` (no user) and has
  no CSRF check (no cookie is read). A valid user session is not a credential
  for it. The token is compared in constant time (`subtle`); only its length
  can leak. It is never logged and `Config`/`SiemIngest` redact it in `Debug`.
- **Order of checks:** token (`401`) -> rate limit (`429`, `Retry-After`) ->
  body size (`413`, 64 KiB) -> JSON (`400`) -> alert shape (`422`, names the
  field, never the value) -> publish. The limiter (the existing fixed-window
  `ScanSubmissionRateLimiter`, 120 per 60 s, one fixed key for the route) runs
  after authentication so unauthenticated traffic cannot use up the quota.
  Behind the ALB a per-IP key would be the balancer's address.
- **Mapping rules:** `rule.level` must be an integer 0..15 (D-18 bands give
  `severity`); `rule.id` may be a string or an integer; ids must match
  `^[A-Za-z0-9_.-]{1,64}$`; `description`/`signature` are cut to 256 and
  `agent.name` to 128 characters (on a char boundary); IPs that do not parse
  are dropped.
- **Publishing is awaited:** unlike `emit`, the handler waits for the Kinesis
  publish (the AP-07 retry policy, 5 s cap) and answers `202`, or `503` so the
  integration can retry. Delivery stays at-least-once.
- **Limitations accepted:** the limiter is in memory and per instance; with
  `SECURITY_EVENTS_STREAM_NAME` unset the publisher is a no-op and alerts are
  accepted and discarded (startup warning); fixtures are representative
  samples written from the Wazuh alert format, not captured from a live system.

