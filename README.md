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

Stack: Rust (async con `tokio`), API HTTP con `axum`, cliente RabbitMQ con
`lapin` (contrato fijado por `broker/`), OIDC contra Google con
`openidconnect`, sesión propia firmada con `jsonwebtoken`, tests de
integración con `testcontainers`.

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

### Desarrollo asistido por IA

El trabajo con agentes usa gentle-ai: cada feature sustancial tiene un
documento de tareas en `odd/tasks/<feature>.md` (Organic Driven Development,
espejado en Engram bajo `odd/<feature>/tasks`). El plan maestro del despliegue
está en el repo `infra`, `odd/tasks/cloud-native-deploy.md`.

Antes de implementar la feature `scan_submission`, lee
`docs/architecture.md` §"Dependencia pendiente": el origen de
`network_user`/`ssh_credentials_ref`/`has_sudo` requiere una API nueva en
`user-service` que todavía no existe.

## Despliegue (Docker)

El `Dockerfile` de la raíz produce una imagen multi-stage:

- **builder**: `rust:1.98-bookworm`, compila el binario `gateway` (nombre
  por defecto del paquete: `Cargo.toml` no declara `[[bin]]`) en release.
- **runtime**: `gcr.io/distroless/cc-debian12:nonroot`, contiene únicamente
  el binario `gateway` y los certificados CA del sistema (ya incluidos en
  la imagen base distroless — necesarios porque este binario abre TLS
  saliente hacia Google, `ms-usuarios` y el Broker), y corre como usuario
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
| `BROKER_AMQPS_URL` | Sí | URL AMQPS del Broker, incluida la credencial del usuario RabbitMQ `gateway`. Nunca se loggea |
| `BROKER_VHOST` | Sí | Vhost de RabbitMQ a usar en el Broker |
| `AWS_REGION` | Sí | Región de AWS de los clientes SNS/SQS. Las credenciales vienen de la cadena de proveedores por defecto de AWS (rol de la tarea ECS), nunca de claves estáticas |
| `AWS_ENDPOINT_URL` | No | Endpoint alternativo de AWS, solo LocalStack. Si se define debe ser una URL válida |
| `SCAN_REQUESTS_TOPIC_ARN` | Sí | ARN del topic SNS de solicitudes de escaneo (`arn:<partición>:sns:<región>:<cuenta>:<nombre>`) |
| `SCAN_CANCELLATIONS_TOPIC_ARN` | Sí | ARN del topic SNS de cancelaciones de escaneo |
| `GATEWAY_SCAN_OUTCOMES_QUEUE_URL` | Sí | URL de la cola SQS de la que Gateway consume los resultados de escaneo |
| `GATEWAY_SCAN_OUTCOMES_DLQ_URL` | Sí | URL de la dead-letter queue de la cola de resultados |
| `FRONT_BASE_URL` | Sí | URL fija de `front` a la que `GET /auth/callback` redirige (`302`) tras completar el login; nunca se deriva de la request (evita open redirect) |
| `MS_USUARIOS_BASE_URL` | Sí | URL base de `ms-usuarios`, nunca expuesta a `front` |
| `MS_USUARIOS_SHARED_SECRET` | Sí | Credencial de servicio compartida con `ms-usuarios`. Nunca se loggea |
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
  -e BROKER_AMQPS_URL=amqps://gateway:change-me@broker.internal:5671 \
  -e BROKER_VHOST=security-app \
  -e FRONT_BASE_URL=https://front.example/post-login \
  -e MS_USUARIOS_BASE_URL=http://ms-usuarios.internal \
  -e MS_USUARIOS_SHARED_SECRET=change-me \
  -e SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS=5 \
  -e SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS=60 \
  -p 8080:8080 \
  gateway:local
```

Los valores de ejemplo de arriba (`change-me`, `broker.internal`,
`ms-usuarios.internal`) son sintéticos, no credenciales reales — nunca se
usan credenciales de producción para verificar que el proceso arranca (ver
`docs/security-scope.md`). Con configuración completa pero sin
conectividad real a Google/`ms-usuarios`/el Broker, el proceso arranca y
falla al conectar (no panickea) al primer intento de uso de esas
dependencias — comportamiento esperado fuera de un entorno con esos
servicios disponibles.
