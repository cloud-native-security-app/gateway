# gateway

API Manager / Gateway: el único componente público de una plataforma de
ciberseguridad blue/red team. Hace el login delegado contra Google
(OAuth 2.0 / OIDC, RF-01), centraliza el enrutamiento hacia los
microservicios internos ocultando su ubicación real (RF-09/RF-10), valida
y encola solicitudes de escaneo (RF-02/RF-03/RF-04), refleja su estado en
tiempo real vía SSE (RF-07/RF-08), aplica rate limiting por usuario
(RF-12) y documenta su propia API (RNF-08).

Este repo implementa **únicamente** `gateway`. `ms-usuarios`, `ms-nmap`,
`ms-analisis`, el Broker y `front` viven en otros repos.

Stack: Rust (async con `tokio`), API HTTP con `axum`, mensajería con el SDK
de AWS (`aws-sdk-sns` para publicar y `aws-sdk-sqs` para consumir; contrato
de mensajes fijado por `broker/`), OIDC contra Google con `openidconnect`,
sesión propia firmada con `jsonwebtoken`, tests de integración con
`testcontainers` + LocalStack.

## API de escaneos

Todas las rutas requieren la cookie de sesión (`401` sin ella). El contrato
completo está en `GET /api/openapi.json`.

| Método y ruta | Respuesta |
|---|---|
| `POST /api/scans` | Alta de escaneo; cuerpo `{"target", "mode"?}` con `mode` `"ssh"` (por defecto) o `"network"` (ver abajo); devuelve `{"scanId"}` |
| `GET /api/me` | Identidad de la sesión (`sub`, `email`, `name`, `role`) y `can_network_scan` (booleano, leído de `ms-usuarios` en cada llamada; `false` si no responde) |
| `GET /api/scans` | Histórico: `scanId` (si se conoce), `mode` (`ssh`/`network`, del histórico persistido en `ms-usuarios`), `target`, `status` (`PENDIENTE`, `EN_PROGRESO`, `COMPLETADO`, `FALLIDO`, `CANCELADO`), `requested_at`, `updated_at`, `failure_reason` (`null` si no hay), `email_status` (`pending`/`sent`/`failed`/`disabled`, solo en `COMPLETADO`; ausente en otros estados) y `emailed_at` (solo con `sent`) |
| `GET /api/scans/{scan_id}/events` | Stream SSE `started`/`completed`/`failed`/`cancelled`; keep-alive cada 15 s; reenvía el último evento al (re)conectar |
| `POST /api/scans/{scan_id}/cancel` | `202`; `404` ajeno; `409` si ya es terminal (`COMPLETADO`/`FALLIDO`/`CANCELADO`) |
| `GET /api/scans/{scan_id}/report` | `200` con el `ScanResult` (`host`, `ports`, `vulnerabilities`, `scanned_at`); `404` inexistente o ajeno; `409` si aún no hay reporte; `502`/`504` fallo de `ms-usuarios` |

### Modo `network` (IP, nombre de host o URL)

`POST /api/scans` con `"mode": "network"` pide a `ms-nmap` escanear la IP desde
su propio contenedor, sin credenciales SSH. Sin `mode` (o con `"ssh"`) el
comportamiento y el payload publicado no cambian (el modo `ssh` sigue aceptando
solo una IP). El cuerpo sigue siendo `{"target", "mode"}`; en `network`,
`target` puede ser:

- una **IP** (IPv4/IPv6, o un CIDR `/32`/`/128`): igual que siempre, sin
  `target_host` ni `extra_port`;
- un **nombre de host** (RFC 1123: etiquetas de letras, dígitos y guion, hasta
  253 caracteres, sin punto final; se guarda en minúsculas);
- una **URL `http://` o `https://`**: se toman host y puerto, y se ignoran
  ruta, query y fragmento. No se admiten credenciales (`user@`) ni otros
  esquemas. Si el host de la URL es una IP se trata como una IP más el puerto.

Un nombre se resuelve en el Gateway (timeout `NETWORK_SCAN_RESOLVE_TIMEOUT_SECS`),
se evalúa **cada** dirección resuelta y se publica una sola, fijada: la primera
IPv4 en el orden del resolvedor o, si no hay, la primera IPv6. `ms-nmap` nunca
recibe el nombre como objetivo (ver `docs/decisions.md` D-20). El `ScanRequest`
lleva `ip` (la fijada), `target_host` (solo con nombre o URL con nombre) y
`extra_port` (solo si la URL trae un puerto explícito distinto de 80 y 443, que
nmap ya escanea por defecto). El histórico guarda el nombre tal como se escribió
(minúsculas, sin esquema ni ruta) o la IP; el evento `scan.requested` mantiene
`target` = IP fijada y añade `target_host`.

| Paso (en este orden) | Resultado |
|---|---|
| Permiso `network_scan` re-validado contra `ms-usuarios` en cada solicitud (`GET /users/me`, campo `can_network_scan`; sin caché) | `403` `{"error":"network_scan_not_permitted"}` si no lo tiene o el usuario no existe; `503` `{"error":"network_scan_permission_unavailable"}` si no se puede confirmar (fail closed) |
| `target` es una IP, un nombre de host o una URL `http`/`https` sin credenciales (se parsea antes de cualquier DNS) | `400` (también con credenciales en la URL, otro esquema, puerto `0`/fuera de rango o etiqueta inválida) |
| Denylist fija: loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), unique-local IPv6 (`fc00::/7`, incluye el metadata `fd00:ec2::254`), multicast (`224.0.0.0/4`, `ff00::/8`), broadcast, sin especificar (`0.0.0.0`, `::`) y sus formas IPv6 que envuelven un IPv4 (`::ffff:127.0.0.1`, `::127.0.0.1`) | `422` `{"error":"network_scan_target_rejected","reason":<código>}` con `target_loopback`, `target_link_local`, `target_unique_local`, `target_multicast`, `target_broadcast` o `target_unspecified` |
| Allowlist `NETWORK_SCAN_ALLOWED_CIDRS`, si está definida | `422` con `reason` `target_outside_allowed_ranges` |
| Nombre sin direcciones, con error de DNS o que supera el timeout | `422` con `reason` `target_unresolvable` |
| Nombre con **alguna** dirección resuelta que incumple la denylist o la allowlist | `422` con `reason` `target_resolves_to_denied` (no indica cuál dirección) |

No se resuelven credenciales SSH (no hay `422` por credencial ausente), se
publica un `ScanRequest` con `scan_mode: "network"` y sin
`network_user`/`ssh_credentials_ref`/`has_sudo`, y el evento `scan.requested`
lleva `scan_mode: "network"` (en `ssh` el evento no cambia). Si se rechaza, no
se registra histórico ni se publica nada. Cuenta contra el mismo límite de tasa
que los escaneos `ssh`. El Gateway envía `scan_mode: "network"` al registrar el
histórico en `ms-usuarios` (en `ssh` el cuerpo no cambia) y `GET /api/scans` lee
`mode` de ese histórico, así que sobrevive a un reinicio; si `ms-usuarios` no lo
devuelve usa la memoria del Gateway y, si tampoco, lo omite (ver
`docs/decisions.md` D-18 y D-19).

El stream SSE de un escaneo envía un comentario keep-alive cada 15 s (para que
el balanceador no lo cierre por inactividad) y, al conectarse o reconectarse,
empieza con el último evento conocido de ese `scanId`; si ya era terminal lo
emite y se cierra. Un `scanId` sin evento recordado (expirado a los 15 min de
terminar, o tras un reinicio) no emite nada y queda abierto. Si el usuario pidió
cancelar, el fallo de `ms-nmap` llega como `{"status":"cancelled",...}` (mismo
JSON que `failed`).

Al terminar un escaneo, el Gateway guarda en `ms-usuarios` el resultado completo
(`COMPLETADO`) o el motivo (`FALLIDO`/`CANCELADO`). Si el usuario pidió cancelar
el escaneo por este Gateway, el evento `failed` de `ms-nmap` se registra como
`CANCELADO`. Esa marca vive en memoria: tras un reinicio del Gateway el escaneo
queda `FALLIDO` con el motivo de cancelación de `ms-nmap`. El `scanId` también
es solo memoria, así que tras un reinicio el reporte de escaneos anteriores
responde `404`.

## Desarrollo

Documentación de referencia, en este orden: `docs/architecture.md`
(responsabilidades y decisiones de diseño), `docs/conventions.md`,
`docs/verification.md`, `docs/security-scope.md` (límites de sesión, OIDC y
credenciales) y `docs/decisions.md` (registro de decisiones técnicas).

### Verificación local

```
make verify   # cargo fmt --check, clippy -D warnings, test, test --ignored, doc
make check    # igual, sin los tests que requieren Docker
```

Requiere Rust 1.98 (el mismo del `Dockerfile`; `rustup` en `~/.cargo/bin`, que
el `Makefile` añade al `PATH`). Los tests de integración usan `testcontainers`
y necesitan Docker; si no está disponible, `make verify` falla en ese paso y
se debe reportar el bloqueo, nunca reemplazar esos tests por mocks.

#### Tests de integración con LocalStack

Todos los tests `#[ignore = "requiere Docker"]` (`cargo test -- --ignored`)
levantan su propio contenedor `localstack/localstack:4.4` (SNS + SQS, sin
cuenta AWS ni token de LocalStack): crean topics, colas, suscripciones
`RawMessageDelivery` y una DLQ con `RedrivePolicy` en cada test, y usan
credenciales ficticias. El arnés compartido está en `tests/common/mod.rs`.
La primera ejecución descarga la imagen. Para un solo archivo:
`cargo test --test scan_outcome_relay -- --ignored`.

#### Ejecución local contra LocalStack

El `docker-compose` de desarrollo (con LocalStack) vive en el repo `infra`,
no aquí. Con un LocalStack ya corriendo en `http://localhost:4566`, y los
topics/colas creados, basta exportar `AWS_ENDPOINT_URL=http://localhost:4566`,
`AWS_REGION=us-east-1`, `AWS_ACCESS_KEY_ID=test`, `AWS_SECRET_ACCESS_KEY=test`
y las variables `SCAN_*`/`GATEWAY_SCAN_OUTCOMES_*` de la tabla de abajo. Para
ver los eventos de seguridad localmente, añadir `SECURITY_EVENTS_STREAM_NAME=security-events`
(el stream lo crea el init de LocalStack de `infra`).

#### Apagado ordenado

`gateway` captura `SIGTERM` (lo que envía ECS al detener una tarea) y
`Ctrl-C`: deja de aceptar conexiones, drena las abiertas hasta 10 s, cancela
el consumidor SQS (un mensaje en proceso termina antes; los que no se
borraron reaparecen en la cola) y espera hasta 10 s a que termine. Ver
`gateway::run`.

### Desarrollo asistido por IA

El trabajo con agentes usa gentle-ai: cada feature sustancial tiene un
documento de tareas en `odd/tasks/<feature>.md` (Organic Driven Development,
espejado en Engram bajo `odd/<feature>/tasks`). El plan maestro del despliegue
está en el repo `infra`, `odd/tasks/cloud-native-deploy.md`.

Antes de implementar la feature `scan_submission`, lee
`docs/architecture.md` §"Dependencia pendiente": el origen de
`network_user`/`ssh_credentials_ref`/`has_sudo` requiere una API nueva en
`user-service` que todavía no existe.

## CI/CD

### En cada pull request y push a `develop` (`.github/workflows/ci.yml`)

- **verify**: Rust 1.98 (el mismo del builder del `Dockerfile`) y `make verify`
  (fmt, clippy `-D warnings`, `cargo test`, `cargo test -- --ignored` contra
  LocalStack con Docker, `cargo doc`).
- **docker-build**: `docker build .` sin push.

### En push a `main` (`.github/workflows/deploy.yml`)

Construye la imagen, la publica en ECR como `security-app/gateway:<sha>` (y
`:latest`) y despliega en el servicio ECS `gateway` del cluster
`security-app-cluster-v2`. Terraform (repo `infra`) es la única fuente de
verdad de la task definition (variables de entorno, secretos de SSM, roles,
logs): CI solo descarga la task definition más reciente de la familia del servicio (no la que está corriendo, así no se pierden los cambios que registró Terraform), cambia la
imagen del contenedor `gateway` por `<sha>`, registra la nueva revisión y
espera la estabilidad del servicio. Nada de esto se versiona en este repo.

Requisitos en GitHub (Learner Lab no tiene OIDC; los fija
`scripts/refresh-gh-secrets.sh` del repo `infra`):

| Nombre | Tipo | Quién lo define |
|--------|------|-----------------|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | secrets del repo | `infra` `scripts/refresh-gh-secrets.sh` |
| `AWS_REGION` | variable del repo | `infra` `scripts/refresh-gh-secrets.sh` |

Las credenciales de Learner Lab caducan: si el deploy falla al autenticarse,
ejecuta `scripts/refresh-gh-secrets.sh` en `infra` y vuelve a lanzar el workflow.

### Redeploy manual y rollback

- Redeploy: pestaña Actions, workflow **Deploy**, **Run workflow**
  (`workflow_dispatch`).
- Rollback: lanza **Run workflow** eligiendo la ref (rama o tag) de un commit
  anterior, que reconstruye y despliega esa imagen; o, sin reconstruir,
  `aws ecs update-service --cluster security-app-cluster-v2 --service gateway --task-definition <familia>:<revisión anterior>`.

## Despliegue (Docker)

El `Dockerfile` de la raíz produce una imagen multi-stage:

- **builder**: `rust:1.98-bookworm`, compila el binario `gateway` (nombre
  por defecto del paquete: `Cargo.toml` no declara `[[bin]]`) en release.
- **runtime**: `gcr.io/distroless/cc-debian12:nonroot`, contiene únicamente
  el binario `gateway` y los certificados CA del sistema (ya incluidos en
  la imagen base distroless — necesarios porque este binario abre TLS
  saliente hacia Google, `ms-usuarios` y los endpoints de SNS/SQS), y corre como usuario
  no-root (`nonroot`, uid 65532).

La imagen final **no incluye**: la toolchain de Rust, el código fuente, ni
shell/coreutils (no hay `sh`, `ls`, gestor de paquetes, etc. — es una imagen
`distroless`).

### Construir

```
docker build -t gateway:local .
```

### Ejecutar

`gateway` lee **toda** su configuración de variables de entorno (ver
`src/config.rs`). Si falta alguna de las requeridas, el proceso termina con
un error tipado explícito, nunca con un panic:

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `HTTP_HOST` | Sí | Host en el que el servidor HTTP hace bind (p. ej. `0.0.0.0` dentro del contenedor) |
| `HTTP_PORT` | Sí | Puerto en el que el servidor HTTP hace bind |
| `GOOGLE_CLIENT_ID` | Sí | `client_id` OAuth de Google (RF-01) |
| `GOOGLE_CLIENT_SECRET` | Sí | `client_secret` OAuth de Google. Nunca se loggea |
| `GOOGLE_REDIRECT_URI` | Sí | URI de redirección registrada ante Google para `GET /auth/callback` |
| `GOOGLE_OIDC_ISSUER_URL` | No (por defecto `https://accounts.google.com`) | Issuer OIDC contra el que se hace el handshake; se sobreescribe solo para apuntar a un IdP de prueba |
| `SESSION_SIGNING_KEY` | Sí | Clave de firma de la sesión propia de Gateway (`jsonwebtoken`). Nunca se loggea |
| `SESSION_TTL_SECS` | Sí | Tiempo de vida, en segundos, de la sesión propia de Gateway |
| `AWS_REGION` | Sí | Región de AWS de los clientes SNS/SQS. Las credenciales vienen de la cadena de proveedores por defecto de AWS (rol de la tarea ECS), nunca de claves estáticas |
| `AWS_ENDPOINT_URL` | No | Endpoint alternativo de AWS, solo LocalStack. Si se define debe ser una URL válida |
| `SECURITY_EVENTS_STREAM_NAME` | No | Nombre del Kinesis Data Stream de eventos de seguridad (`security-events`). Si no se define o está vacía, Gateway no publica eventos (un aviso informativo al arrancar). El panel de administración lo sirve `events-service`, no este proceso. Solo admite `[a-zA-Z0-9_.-]`, hasta 128 caracteres. Usa `AWS_REGION`/`AWS_ENDPOINT_URL` y las credenciales por defecto de AWS; un fallo de Kinesis solo se loggea y nunca altera una respuesta |
| `ADMIN_EVENTS_ROLE_RECHECK_SECS` | No (por defecto `60`) | Cada cuántos segundos un stream SSE de `GET /api/admin/events` reconsulta el rol vigente del usuario en `ms-usuarios` y lo cierra si ya no es admin o no se puede verificar. Entero mayor que cero |
| `NETWORK_SCAN_RESOLVE_TIMEOUT_SECS` | No (por defecto `5`) | Tiempo máximo, en segundos, de la resolución DNS de un objetivo `network` dado por nombre o URL; al agotarse responde `422` `target_unresolvable`. Entero mayor que cero |
| `NETWORK_SCAN_ALLOWED_CIDRS` | No | Lista de CIDR separados por coma (`10.0.0.0/24,2001:db8::/32`) a los que se limita el modo `network` de `POST /api/scans`; un objetivo fuera de ellos recibe `422`. Vacía o sin definir = cualquier objetivo que pase la denylist fija (que ninguna allowlist puede anular). Un elemento que no sea un CIDR con prefijo hace fallar el arranque con `ConfigError::InvalidCidrList` (el valor no se imprime) |
| `SIEM_INGEST_TOKEN` | No | Bearer token of `POST /api/integrations/siem/alerts` (Wazuh alert ingestion, one alert per request, body up to 64 KiB, rate limited per `SIEM_INGEST_RATE_LIMIT`). Unset or blank = feature off: the route is not mounted and answers like any unknown path. When set, send `Authorization: Bearer <token>`; a missing or wrong token gets `401`. Use a long random value (e.g. `openssl rand -hex 32`). Redacted in `Debug` and never logged. Alerts are published as `siem.alert` events, so `SECURITY_EVENTS_STREAM_NAME` must also be set; otherwise the gateway starts with a warning and the route answers `503` |
| `SIEM_INGEST_RATE_LIMIT` | No | Alerts `POST /api/integrations/siem/alerts` accepts per 60 s window (single bucket for the whole route, counted only after the token check). Default `120`; a positive integer (up to `4294967295`). Read only when `SIEM_INGEST_TOKEN` is set; an invalid value (not a number, `0`, negative, too large) makes the gateway fail at startup naming this variable. Bursts beyond the limit get `429` with `Retry-After`, and Wazuh does not retry a rejected alert, so size the limit for your peak alert rate or filter by `level` in the Wazuh integration |
| `SCAN_REQUESTS_TOPIC_ARN` | Sí | ARN del topic SNS de solicitudes de escaneo (`arn:<partición>:sns:<región>:<cuenta>:<nombre>`) |
| `SCAN_CANCELLATIONS_TOPIC_ARN` | Sí | ARN del topic SNS de cancelaciones de escaneo |
| `GATEWAY_SCAN_OUTCOMES_QUEUE_URL` | Sí | URL de la cola SQS de la que Gateway consume los resultados de escaneo |
| `GATEWAY_SCAN_OUTCOMES_DLQ_URL` | Sí | URL de la dead-letter queue de la cola de resultados |
| `FRONT_BASE_URL` | Sí | URL fija de `front` a la que `GET /auth/callback` redirige (`302`) tras completar el login; nunca se deriva de la request (evita open redirect) |
| `MS_USUARIOS_BASE_URL` | Sí | URL base de `ms-usuarios`, nunca expuesta a `front` |
| `MS_USUARIOS_SHARED_SECRET` | Sí | Credencial de servicio compartida con `ms-usuarios`. Nunca se loggea |
| `EVENTS_SERVICE_BASE_URL` | Sí | URL base de `events-service` (proxy de `/api/admin/*`), nunca expuesta a `front` |
| `EVENTS_SERVICE_SHARED_SECRET` | Sí | Credencial de servicio compartida con `events-service` (header `X-Gateway-Secret`). Nunca se loggea |
| `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS` | Sí | Número máximo de `POST /api/scans` por usuario dentro de la ventana de tiempo (RF-12) |
| `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS` | Sí | Duración, en segundos, de esa ventana de tiempo |

```
docker run --rm \
  -e HTTP_HOST=0.0.0.0 \
  -e HTTP_PORT=8080 \
  -e GOOGLE_CLIENT_ID=change-me \
  -e GOOGLE_CLIENT_SECRET=change-me \
  -e GOOGLE_REDIRECT_URI=https://gateway.example/auth/callback \
  -e SESSION_SIGNING_KEY=change-me \
  -e SESSION_TTL_SECS=3600 \
  -e AWS_REGION=us-east-1 \
  -e SCAN_REQUESTS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:scan-requests \
  -e SCAN_CANCELLATIONS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:scan-cancellations \
  -e GATEWAY_SCAN_OUTCOMES_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes \
  -e GATEWAY_SCAN_OUTCOMES_DLQ_URL=https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes-dlq \
  -e FRONT_BASE_URL=https://front.example/post-login \
  -e MS_USUARIOS_BASE_URL=http://ms-usuarios.internal \
  -e MS_USUARIOS_SHARED_SECRET=change-me \
  -e EVENTS_SERVICE_BASE_URL=http://events-service.internal \
  -e EVENTS_SERVICE_SHARED_SECRET=change-me \
  -e SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS=5 \
  -e SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS=60 \
  -p 8080:8080 \
  gateway:local
```

Los valores de ejemplo de arriba (`change-me`, `123456789012`,
`ms-usuarios.internal`) son sintéticos, no credenciales reales — nunca se
usan credenciales de producción para verificar que el proceso arranca (ver
`docs/security-scope.md`). Con configuración completa pero sin
conectividad real a Google/`ms-usuarios`/SNS/SQS, el proceso arranca y
falla al conectar (no panickea) al primer intento de uso de esas
dependencias — comportamiento esperado fuera de un entorno con esos
servicios disponibles.
