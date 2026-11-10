# Arquitectura — Qué significa "hacer un buen trabajo"

> Este documento define el estándar de calidad. Los agentes revisores
> evalúan código contra este archivo. Si no está aquí, no es un requisito.

## Alcance de este repo

Este repo implementa **únicamente el API Manager / Gateway**: el único
componente de la plataforma expuesto en subred pública (ver diagrama de
arquitectura). `ms-usuarios`, `ms-nmap`, `ms-analisis`, el Broker y `front`
son otros repos — este repo no conoce su lógica interna, solo los contratos
que ya documentan (`broker/contracts/`, la topología SNS/SQS de `broker/`,
`user-service/docs/architecture.md`, `front/docs/architecture.md`).

```
Browser (front) ──HTTPS──▶ Gateway ──▶ Identity Provider (Google OAuth2/OIDC, RF-01)
                              │
                              ├──(HTTP síncrono, subred privada)──▶ ms-usuarios
                              │
                              └──(HTTPS)──▶ SNS ──▶ ms-nmap
                                              │
                                   cola SQS de resultados (SSE hacia front)
```

## Responsabilidades

Gateway es el único componente público (subred pública); todo lo demás
(`ms-usuarios`, `ms-nmap`, `ms-analisis`, el Broker y sus bases de datos)
vive en subred privada sin exposición directa a internet (RNF-03).

- Handshake OAuth 2.0 / OIDC contra Google y sesión propia (RF-01, RNF-02,
  RF-10); `front` nunca ve el token de Google.
- Enrutamiento centralizado hacia los servicios internos, ocultando su
  ubicación real (RF-09): hoy `ms-usuarios` (HTTP síncrono) y el Broker
  (`ScanRequest`/`ScanCancellation` publicados, `ScanOutcome` consumido).
- Validación de IP única (o CIDR /32, /128) (RF-02/RF-03), encolado en el Broker y respuesta
  inmediata con un `scanId` (RF-04; RNF-04: `POST` en < 500 ms).
- Avance de escaneos en tiempo real por SSE (RF-07/RF-08), rate limiting por
  usuario (RF-12) y documentación OpenAPI (RNF-08).

Fuera de alcance: lógica de negocio de `ms-usuarios`, `ms-nmap`,
`ms-analisis`, el Broker y `front`.

## Decisiones de diseño ya tomadas

- **Gateway hace el handshake OIDC, nunca `front`.** `front` solo redirige
  el navegador a `GET /auth/login`; Gateway completa el intercambio con
  Google (código → tokens), valida el **ID token de Google** (firma vía
  JWKS, `aud`, `iss`, `exp`) con la crate `openidconnect`, y descarta ese
  token tras extraer la identidad (`sub`, `email`, nombre) — nunca lo
  reenvía ni lo persiste.
- **Gateway emite su propia sesión firmada** (JWT propio, crate
  `jsonwebtoken`, secreto/clave de firma en `Config`) que encapsula esa
  identidad ya verificada, con `exp` corto y renovable. Se entrega como
  cookie `HttpOnly` + `Secure` + `SameSite=Strict`. **Esto es lo que RNF-02
  exige validar "en cada solicitud"**: no se re-valida el ID token de
  Google en cada request (solo una vez, durante el login) — se valida la
  sesión propia de Gateway, más barata y sin dependencia de red hacia
  Google en el camino caliente.
- **`ms-usuarios` nunca ve la sesión de Gateway tal cual.** Cada llamada
  síncrona de Gateway hacia `ms-usuarios` reenvía la identidad ya verificada
  en un header propio (mismo contrato que ya documenta
  `user-service/docs/security-scope.md`: `ms-usuarios` exige un header de
  identidad + una credencial de servicio `GATEWAY_SHARED_SECRET`). Gateway
  es quien posee y envía esa credencial de servicio — `ms-usuarios` no
  sabe nada de Google ni de JWTs.
- **Broker: SNS + SQS, contrato fijado por `broker/`** (reemplaza a
  RabbitMQ/`lapin`, ver `docs/decisions.md` D-15). Gateway publica
  `ScanRequest`/`ScanCancellation` en dos topics SNS (atributo de mensaje
  `routing_key`) y consume los resultados de una cola SQS con su DLQ. Este
  repo **no** crea ni redefine topics, colas, suscripciones ni permisos: los
  provee `broker`/Terraform y el rol de la tarea ECS (credenciales por la
  cadena por defecto de AWS).
- **Los tests de integración crean su propia topología en LocalStack**
  (topics, colas con suscripción raw y DLQ con `RedrivePolicy`), siguiendo
  los nombres y atributos del contrato de `broker/`; si ese contrato cambia,
  el arnés de `tests/common/mod.rs` se actualiza explícitamente.
- **Notificación en tiempo real vía SSE hacia `front` (RF-08)**, coherente
  con la decisión ya tomada en `front/docs/architecture.md`: Gateway
  consume `gateway.scan-outcomes` (bindeada a las 3 variantes de
  `ScanOutcome`: `started`/`completed`/`failed`) y relaya cada evento al
  stream SSE del `scanId` correspondiente.
- **El consumidor SQS no muere en silencio y se apaga de forma ordenada.**
  `SqsScanOutcomeConsumer::run` solo sale por shutdown: los errores de
  recepción se loggean y se reintentan con backoff exponencial (1-30 s). Un
  mensaje se borra solo después de que el handler retorna (entrega al menos
  una vez, el handler tolera duplicados); un malformado va a la DLQ. El
  publicador SNS no mantiene conexión que reconectar (cada `Publish` es una
  llamada HTTPS independiente). `gateway::run` captura `SIGTERM`/`Ctrl-C`,
  cancela el consumidor, drena HTTP y espera al consumidor con tiempos
  acotados.
- **Rate limiting por usuario (RF-12)** con un limitador en memoria propio sobre la ruta
  de encolado de escaneos, con la identidad de la sesión de Gateway como
  clave (no la IP del cliente, que puede compartirse tras un NAT/proxy).
- **OpenAPI/Swagger (RNF-08)** generado desde el propio código (p. ej.
  `utoipa`) para toda ruta pública de este Gateway — nunca mantenido a mano
  en paralelo al código.

## Dependencia pendiente: origen de `network_user`/`ssh_credentials_ref`/`has_sudo`

`front` solo recoge una única IP del usuario (ver
`front/docs/architecture.md`), pero el `ScanRequest` que exige
`broker/contracts/scan-request.schema.json` (copiado literal de `ms-nmap`)
requiere además `network_user`, `ssh_credentials_ref` (credencial SSH real)
y `has_sudo`. La decisión tomada con el usuario es que **`ms-usuarios`
guardará esos datos por usuario/objetivo**, pero **esa API todavía no existe
en `user-service`** (no estaba entre sus features a la fecha de este
documento).

Mientras esa dependencia no exista:

- La feature `scan_submission` de este repo implementa la llamada a `ms-usuarios` para resolver esos 3 campos **contra
  el contrato que se acuerde cuando esa feature se añada en `user-service`**
  — no se inventa aquí el shape de esa respuesta.
- Si la llamada falla porque el endpoint no existe todavía (404) o porque
  `ms-usuarios` no tiene credenciales configuradas para ese usuario/objetivo,
  Gateway responde con un error explícito y tipado (p. ej. `501 Not
  Implemented` o `422` con un motivo claro) — **nunca** con credenciales
  hardcodeadas, de ejemplo, o inventadas para "que funcione".
- Esta sección se actualiza (y dejará de ser un bloqueo) cuando
  `user-service` publique esa API — es responsabilidad del `leader` de una
  sesión futura verificarlo antes de dar por buena la feature
  `scan_submission`.

## Otra dependencia pendiente (documentada, no bloqueante para este repo)

La visualización del reporte final (RF-11) requiere consultar a
`ms-analisis`, que **todavía no existe como repo**. Este repo no implementa
ningún endpoint de reporte hasta que `ms-analisis` exista y documente su
propio contrato — no se asume aquí su forma. `front/docs` ya tiene una
feature de UI para esto (`report_view`); el endpoint de Gateway
correspondiente se añade cuando esa dependencia se
resuelva, no antes.

## Capas

1. **`config`** — carga de configuración desde variables de entorno
   (credenciales OAuth de Google, secreto de firma de sesión, región,
   ARNs de topics SNS y URLs de colas SQS (sin credenciales: salen de la
   cadena por defecto de AWS), URL base + credencial compartida de
   `ms-usuarios`, umbrales de rate limiting). Sin valores hardcodeados.
2. **`domain`** — tipos puros: `Session` (identidad verificada + `exp`),
   `ScanSubmission` (entrada validada del usuario), `ScanOutcomeEvent`. Sin
   IO.
3. **`auth`** — el handshake OIDC contra Google (`openidconnect`), emisión/
   validación de la sesión propia (`jsonwebtoken`), y el middleware `axum`
   que exige sesión válida en toda ruta protegida.
4. **`usuarios_client`** — único módulo que conoce la URL y el contrato
   HTTP de `ms-usuarios`; nadie más en este repo hace una petición HTTP
   directa hacia `ms-usuarios`.
5. **`broker`, `sns`, `sqs`** — `broker` define los puertos
   (`ScanRequestPublisher`, `ScanOutcomeHandler`) y los tipos de mensaje;
   `sns` publica `ScanRequest`/`ScanCancellation` en SNS y `sqs` consume la
   cola de resultados de escaneo. Únicos módulos que conocen el contrato de
   mensajes del Broker.
6. **`realtime`** — registro de streams SSE activos por `scanId` y el
   puente entre un evento consumido del Broker y los clientes SSE
   suscritos.
7. **`api`** — handlers y router `axum`: login/callback/logout, `GET
   /api/me`, perfil, envío/histórico/cancelación/reporte de escaneos, stream SSE,
   documentación OpenAPI. Aplica el middleware de sesión y el rate
   limiter.
8. **`wiring`** — composition root: construye el cliente OIDC, el publicador
   SNS y el consumidor SQS, el cliente HTTP hacia `ms-usuarios` y arma el router completo
   desde la `Config`.
9. **`lib`** — declara `pub mod` para cada capa anterior y expone `pub
   async fn run(...)` (consumidor SQS de fondo y apagado ordenado).
10. **`main`** — envoltorio delgado: runtime tokio, tracing, config,
    `wiring`, `lib::run(...)`.

No introducir capas adicionales hasta que haya una razón concreta
documentada en `docs/decisions.md` o en el documento de la tarea (`odd/tasks/`).

## Manejo de errores

- Cada capa (`auth`, `usuarios_client`, `broker`, `api`) define su propio
  tipo de error con `thiserror` (variantes específicas, no `String`
  genérico).
- Un fallo de `usuarios_client` o `broker` se traduce en una respuesta HTTP
  de error apropiada — nunca en un panic ni en un proceso que muere en
  silencio.
- El token de Google, la sesión firmada completa, la credencial compartida
  con `ms-usuarios` y los cuerpos de mensaje del Broker nunca aparecen en logs ni en
  cuerpos de error (ver `docs/security-scope.md`).

## Despliegue

> Detalle práctico (variables de entorno exactas, ejemplo de `docker run`)
> vive en `README.md` §"Despliegue (Docker)" — esta sección explica el
> *por qué*, no lo duplica.

Gateway sirve HTTP plano dentro de la subred; la terminación TLS pública
(RNF-01) se asume hecha por un balanceador/ingress delante de este
servicio, no por el propio binario — mismo principio de "no asumir
infraestructura no pedida" que documentan los demás repos de esta
plataforma. Si el despliegue real requiere que Gateway termine TLS él
mismo, es una decisión a discutir explícitamente antes de implementarla.

El servicio se empaqueta con un `Dockerfile` multi-stage (stage builder con
la toolchain Rust, stage runtime mínimo distroless, usuario no-root), mismo
patrón que `user-service`/`nmap-service`. La imagen final incluye
únicamente el binario `gateway` y los certificados CA del sistema (ya
provistos por la base `gcr.io/distroless/cc-debian12:nonroot`) — necesarios
porque este binario es, a su vez, **cliente** TLS saliente hacia tres
destinos distintos: Google (handshake OIDC, RF-01), `ms-usuarios` (HTTP
síncrono, subred privada) y AWS SNS/SQS (HTTPS). Esto es
independiente de la terminación TLS pública descrita arriba, que sigue
siendo responsabilidad de un balanceador/ingress delante de Gateway, no del
propio binario. La imagen final **no incluye** la toolchain de Rust, el
código fuente, ni shell/coreutils — es deliberadamente inspeccionable y de
superficie de ataque mínima. No se asume todavía un proveedor cloud
concreto para el propio servicio — se documenta en términos genéricos hasta
que el usuario decida una plataforma de despliegue.

## Qué NO hacer

- No re-implementar la validación del ID token de Google en cada request
  (solo al login) — es RNF-02 sobre la sesión propia de Gateway.
- No exponer `ms-usuarios`, el Broker, ni ninguna URL/credencial interna a
  `front`.
- No inventar el shape de la API de `ms-usuarios` para
  `network_user`/`ssh_credentials_ref`/`has_sudo` ni el contrato de
  `ms-analisis` — ver "Dependencias pendientes" arriba.
- No redefinir la topología de SNS/SQS (topics, colas, suscripciones,
  permisos) — es fuente de verdad de `broker/`.
