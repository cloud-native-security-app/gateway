# Arquitectura — Qué significa "hacer un buen trabajo"

> Este documento define el estándar de calidad. Los agentes revisores
> evalúan código contra este archivo. Si no está aquí, no es un requisito.

## Alcance de este repo

Este repo implementa **únicamente el API Manager / Gateway**: el único
componente de la plataforma expuesto en subred pública (ver diagrama de
arquitectura). `ms-usuarios`, `ms-nmap`, `ms-analisis`, el Broker y `front`
son otros repos — este repo no conoce su lógica interna, solo los contratos
que ya documentan (`broker/contracts/`, `broker/rabbitmq/definitions.json`,
`user-service/docs/architecture.md`, `front/docs/architecture.md`).

```
Browser (front) ──HTTPS──▶ Gateway ──▶ Identity Provider (Google OAuth2/OIDC, RF-01)
                              │
                              ├──(HTTP síncrono, subred privada)──▶ ms-usuarios
                              │
                              └──(AMQPS)──▶ Broker ──▶ ms-nmap
                                              │
                                   gateway.scan-outcomes (SSE hacia front)
```

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
- **Broker: RabbitMQ real, contrato fijado por `broker/`.** Gateway es el
  primer repo que implementa un cliente `lapin` real contra ese contrato
  (`ms-nmap` todavía usa stubs en memoria — ver
  `nmap-service/docs/architecture.md`). El usuario RabbitMQ `gateway` ya
  existe en `broker/rabbitmq/definitions.json` con permisos de mínimo
  privilegio: `write` solo sobre `scan.requests`/`scan.cancellations`,
  `read` solo sobre `gateway.scan-outcomes`. Este repo **no** redefine esa
  topología — la consume tal cual (AMQPS, puerto 5671, vhost
  `security-app`).
- **El fixture de topología usado en tests de integración se copia
  literalmente de `broker/rabbitmq/definitions.json`** (mismos exchanges,
  colas, bindings y permisos del usuario `gateway`) — no se re-deriva,
  mismo principio que aplica `broker/contracts/README.md` al copiar el
  contrato de mensajes desde `ms-nmap`. Si la topología de `broker/` cambia,
  este fixture se actualiza explícitamente, nunca por inferencia.
- **Notificación en tiempo real vía SSE hacia `front` (RF-08)**, coherente
  con la decisión ya tomada en `front/docs/architecture.md`: Gateway
  consume `gateway.scan-outcomes` (bindeada a las 3 variantes de
  `ScanOutcome`: `started`/`completed`/`failed`) y relaya cada evento al
  stream SSE del `scanId` correspondiente.
- **Rate limiting por usuario (RF-12)** con `tower_governor` sobre la ruta
  de encolado de escaneos, con la identidad de la sesión de Gateway como
  clave (no la IP del cliente, que puede compartirse tras un NAT/proxy).
- **OpenAPI/Swagger (RNF-08)** generado desde el propio código (p. ej.
  `utoipa`) para toda ruta pública de este Gateway — nunca mantenido a mano
  en paralelo al código.

## Dependencia pendiente: origen de `network_user`/`ssh_credentials_ref`/`has_sudo`

`front` solo recoge una IP/rango del usuario (ver
`front/docs/architecture.md`), pero el `ScanRequest` que exige
`broker/contracts/scan-request.schema.json` (copiado literal de `ms-nmap`)
requiere además `network_user`, `ssh_credentials_ref` (credencial SSH real)
y `has_sudo`. La decisión tomada con el usuario es que **`ms-usuarios`
guardará esos datos por usuario/objetivo**, pero **esa API todavía no existe
en `user-service`** (no está en su `feature_list.json` a la fecha de este
documento).

Mientras esa dependencia no exista:

- La feature `scan_submission` de este repo (ver `feature_list.json`)
  implementa la llamada a `ms-usuarios` para resolver esos 3 campos **contra
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
correspondiente se añade a `feature_list.json` cuando esa dependencia se
resuelva, no antes.

## Capas

1. **`config`** — carga de configuración desde variables de entorno
   (credenciales OAuth de Google, secreto de firma de sesión, endpoint/
   vhost/credencial AMQPS del Broker, URL base + credencial compartida de
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
5. **`broker`** — cliente `lapin` sobre AMQPS: `publish_scan_request`,
   `publish_scan_cancellation`, y el consumidor de `gateway.scan-outcomes`.
   Único módulo que conoce el contrato de mensajes del Broker.
6. **`realtime`** — registro de streams SSE activos por `scanId` y el
   puente entre un evento consumido del Broker y los clientes SSE
   suscritos.
7. **`api`** — handlers y router `axum`: login/callback/logout, `GET
   /api/me`, perfil, envío/histórico/cancelación de escaneos, stream SSE,
   documentación OpenAPI. Aplica el middleware de sesión y el rate
   limiter.
8. **`wiring`** — composition root: construye el cliente OIDC, el pool/canal
   `lapin`, el cliente HTTP hacia `ms-usuarios` y arma el router completo
   desde la `Config`.
9. **`lib`** — declara `pub mod` para cada capa anterior y expone `pub
   async fn run(...)`.
10. **`main`** — envoltorio delgado: runtime tokio, tracing, config,
    `wiring`, `lib::run(...)`.

No introducir capas adicionales hasta que haya una razón concreta
documentada en `feature_list.json`.

## Manejo de errores

- Cada capa (`auth`, `usuarios_client`, `broker`, `api`) define su propio
  tipo de error con `thiserror` (variantes específicas, no `String`
  genérico).
- Un fallo de `usuarios_client` o `broker` se traduce en una respuesta HTTP
  de error apropiada — nunca en un panic ni en un proceso que muere en
  silencio.
- El token de Google, la sesión firmada completa, la credencial compartida
  con `ms-usuarios` y la credencial AMQPS nunca aparecen en logs ni en
  cuerpos de error (ver `docs/security-scope.md`).

## Despliegue

> Detalle práctico (variables de entorno exactas) vive en `README.md` una
> vez exista el `Dockerfile` (feature `containerization`) — esta sección
> explica el *por qué*.

Gateway sirve HTTP plano dentro de la subred; la terminación TLS pública
(RNF-01) se asume hecha por un balanceador/ingress delante de este
servicio, no por el propio binario — mismo principio de "no asumir
infraestructura no pedida" que documentan los demás repos de esta
plataforma. Si el despliegue real requiere que Gateway termine TLS él
mismo, es una decisión a discutir explícitamente antes de implementarla.

## Qué NO hacer

- No re-implementar la validación del ID token de Google en cada request
  (solo al login) — es RNF-02 sobre la sesión propia de Gateway.
- No exponer `ms-usuarios`, el Broker, ni ninguna URL/credencial interna a
  `front`.
- No inventar el shape de la API de `ms-usuarios` para
  `network_user`/`ssh_credentials_ref`/`has_sudo` ni el contrato de
  `ms-analisis` — ver "Dependencias pendientes" arriba.
- No redefinir la topología de RabbitMQ (exchanges/colas/permisos) — es
  fuente de verdad de `broker/`.
