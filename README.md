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
| `POST /api/scans` | Alta de escaneo; devuelve `{"scanId"}` |
| `GET /api/scans` | Histórico: `scanId` (si se conoce), `target`, `status` (`PENDIENTE`, `EN_PROGRESO`, `COMPLETADO`, `FALLIDO`, `CANCELADO`), `requested_at`, `updated_at`, `failure_reason` (`null` si no hay) |
| `GET /api/scans/{scan_id}/events` | Stream SSE `started`/`completed`/`failed` |
| `POST /api/scans/{scan_id}/cancel` | `202`; `404` ajeno; `409` si ya es terminal (`COMPLETADO`/`FALLIDO`/`CANCELADO`) |
| `GET /api/scans/{scan_id}/report` | `200` con el `ScanResult` (`host`, `ports`, `vulnerabilities`, `scanned_at`); `404` inexistente o ajeno; `409` si aún no hay reporte; `502`/`504` fallo de `ms-usuarios` |

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
y las variables `SCAN_*`/`GATEWAY_SCAN_OUTCOMES_*` de la tabla de abajo.

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
logs): CI solo descarga la task definition vigente del servicio, cambia la
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
  -e AWS_REGION=us-east-1 \
  -e SCAN_REQUESTS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:scan-requests \
  -e SCAN_CANCELLATIONS_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:scan-cancellations \
  -e GATEWAY_SCAN_OUTCOMES_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes \
  -e GATEWAY_SCAN_OUTCOMES_DLQ_URL=https://sqs.us-east-1.amazonaws.com/123456789012/gateway-scan-outcomes-dlq \
  -e FRONT_BASE_URL=https://front.example/post-login \
  -e MS_USUARIOS_BASE_URL=http://ms-usuarios.internal \
  -e MS_USUARIOS_SHARED_SECRET=change-me \
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
