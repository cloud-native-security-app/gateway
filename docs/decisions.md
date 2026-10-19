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

- **Decisión:** el canal activa `confirm_select` una vez y
  `publish_scan_request` espera el ack real del Broker (no solo el envío del
  frame); el costo es de pocos ms dentro de la subred privada, muy por debajo
  de RNF-04 (< 500 ms). Los errores de publicación se mapean a un `BrokerError` tipado (`thiserror`) que no expone la URL ni la
  credencial AMQPS en su `Display`.

## D-05 — Consumo: mensaje malformado se descarta sin requeue

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
  la imagen base cubren el TLS saliente hacia Google, `ms-usuarios` y el Broker.
