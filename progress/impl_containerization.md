# Implementación — feature 11: containerization

## Archivos creados

- `Dockerfile` (raíz): multi-stage, builder `rust:1.98-bookworm@sha256:...`
  + runtime `gcr.io/distroless/cc-debian12:nonroot@sha256:...`. Reutiliza
  **exactamente los mismos digests** que ya usa `user-service/Dockerfile`
  (mismo `rustc`/`cargo` 1.98.0 que reporta `./init.sh` de este repo, así
  que siguen siendo apropiados aquí). Adaptado respecto al patrón de
  `user-service`:
  - Sin stage de migraciones/sqlx (`gateway` no tiene `migrations/`).
  - `cargo build --release` sin `--bin` explícito: `Cargo.toml` no declara
    `[[bin]]`, así que el único binario producido ya se llama `gateway`
    (nombre del paquete) — confirmado antes de escribir el Dockerfile.
  - Nota explícita en comentarios y en `LABEL` sobre los 3 destinos TLS
    salientes que este binario negocia (Google, `ms-usuarios`, Broker
    AMQPS), no solo uno.
- `.dockerignore`: excluye `target/`, `.git/`, `.gitignore`, `.claude/`,
  `progress/`, `docs/`, `tests/`, `rabbitmq/` (fixtures de topología para
  `testcontainers`, no los usa el binario de producción), `*.md`,
  `Dockerfile`, `.dockerignore`. Verificado que `tests/` y `rabbitmq/` solo
  los usa `cargo test`/`testcontainers`, nunca `cargo build --release`
  (grep de `fixture_path("rabbitmq/...")` confirma que esas rutas solo se
  leen desde `tests/*.rs`, nunca desde `src/`).

## Archivos modificados

- `docs/architecture.md` §"Despliegue": **extendida** (no reemplazada) la
  nota ya existente sobre terminación TLS pública fuera del binario, con un
  párrafo nuevo sobre la imagen (qué incluye/no incluye, mismo patrón que
  `user-service`/`nmap-service`) y la aclaración de que el binario es
  cliente TLS saliente hacia 3 destinos (Google, `ms-usuarios`, Broker).
- `README.md` §"Despliegue (Docker)": relleno completo del placeholder —
  instrucciones de build, tabla de las 14 variables `ENV_*` reales leídas
  de `src/config.rs` (13 requeridas + `GOOGLE_OIDC_ISSUER_URL` con default
  `https://accounts.google.com`, la única opcional), y un `docker run` de
  ejemplo con valores sintéticos (`change-me`, `*.internal`) — nunca
  credenciales reales, conforme a `docs/security-scope.md`.

## Decisiones tomadas

- **Digests reutilizados de `user-service`, no inventados**: mismo
  `rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`
  y `gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`.
  Verificado que la versión de Rust del builder (1.98) coincide con la que
  reporta `./init.sh` de este repo (`rustc 1.98.0`), así que sigue siendo
  apropiado.
- **Variables de entorno verificadas leyendo `src/config.rs` directamente**
  (no de memoria): hay 14 constantes `ENV_*` (no 12 como sugería el
  encargo — se documenta el conteo real encontrado). De ellas, 13 son
  requeridas (`Config::from_env` devuelve `ConfigError::Missing` si falta
  cualquiera, confirmado también por `ALL_REQUIRED_VARS` en los tests de
  `config.rs`): `HTTP_HOST`, `HTTP_PORT`, `GOOGLE_CLIENT_ID`,
  `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `SESSION_SIGNING_KEY`,
  `SESSION_TTL_SECS`, `BROKER_AMQPS_URL`, `BROKER_VHOST`,
  `MS_USUARIOS_BASE_URL`, `MS_USUARIOS_SHARED_SECRET`,
  `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS`,
  `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS`. Solo una tiene default:
  `GOOGLE_OIDC_ISSUER_URL` (default `https://accounts.google.com` vía
  `optional_string_with_default`, no aparece en `ALL_REQUIRED_VARS`). El
  README documenta esta distinción en la columna "Requerida".

## Verificación manual (criterio de aceptación 7)

Ejecutado en este entorno (sin conectividad real a Google/`ms-usuarios`/el
Broker, como se esperaba):

1. `docker build -t gateway:local .` → **completa sin error** en ~101s
   (cachea deps en el stage 1, recompila solo el crate propio en el stage
   2). Imagen final: 51.7MB en disco / 13.4MB de contenido.
2. `docker inspect gateway:local --format '{{.Config.User}}'` → `nonroot`
   (confirma que el contenedor corre como usuario no-root).
3. `docker run --rm --entrypoint sh gateway:local -c "echo hi"` → falla con
   `exec: "sh": executable file not found in $PATH` (confirma que no hay
   shell/toolchain en la imagen final — no es un panic del binario, es el
   runtime de contenedor fallando al no encontrar `sh`).
4. `docker run --rm -e HTTP_HOST=... -e HTTP_PORT=8080 -e
   GOOGLE_CLIENT_ID=lab-client-id -e
   GOOGLE_CLIENT_SECRET=lab-only-not-a-real-secret -e
   GOOGLE_REDIRECT_URI=https://gateway.lab/auth/callback -e
   SESSION_SIGNING_KEY=lab-only-not-a-real-secret -e SESSION_TTL_SECS=3600
   -e BROKER_AMQPS_URL=amqps://gateway:lab-only-not-a-real-secret@broker.lab:5671
   -e BROKER_VHOST=security-app -e
   MS_USUARIOS_BASE_URL=http://ms-usuarios.lab -e
   MS_USUARIOS_SHARED_SECRET=lab-only-not-a-real-secret -e
   SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS=5 -e
   SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS=60 -p 18080:8080 gateway:local`
   (todas las 13 variables requeridas presentes, valores sintéticos de
   laboratorio, nunca reales) → el proceso **arranca**, carga la
   configuración correctamente (no hay error de `ConfigError`), intenta la
   inicialización del `wiring` (conectar a Google/Broker/ms-usuarios,
   inexistentes en este entorno) y termina con un log `ERROR` estructurado
   (`el proceso de gateway terminó con un error fatal
   error=no se pudo completar la inicialización del servicio`) y código de
   salida 1 — **ningún panic**, ningún stack trace, ninguna credencial en
   el log. Comportamiento esperado y correcto para un entorno sin esas 3
   dependencias reales disponibles.
5. Limpieza: contenedores lanzados con `--rm` (no quedan huérfanos);
   imagen `gateway:local` eliminada explícitamente al terminar
   (`docker rmi gateway:local`). `docker ps -a` no muestra containers de
   `gateway` remanentes.

## `./init.sh`

Ejecutado tras los cambios (antes de la verificación Docker, y no se tocó
`src/`/`tests/` después): exit code 0, todas las secciones `[OK]`
(`cargo fmt`, `clippy`, `cargo test`, `cargo test -- --ignored` contra
RabbitMQ real vía testcontainers, `cargo doc`). No se detectó ningún
efecto colateral de esta feature sobre el resto del repo (es
Dockerfile/.dockerignore/docs/README, no toca `src/`/`tests/`).

## Verificación de los 8 criterios de aceptación

1. ✅ `Dockerfile` multi-stage en la raíz, builder Rust + runtime
   distroless/cc con el binario + certificados CA.
2. ✅ Imagen final sin toolchain ni código fuente (solo `COPY
   --from=builder .../gateway`, sin `COPY src` en el stage final; sin
   shell, confirmado en el punto 3 de verificación manual).
3. ✅ `USER nonroot`, confirmado con `docker inspect`.
4. ✅ Tabla de env vars en `README.md`, derivada de leer `src/config.rs`
   directamente (14 `ENV_*`, 13 requeridas + 1 con default).
5. ✅ `.dockerignore` excluye `target/`, `.git/`, `.claude/`, `progress/`,
   `docs/` (y adicionalmente `tests/`, `rabbitmq/`, `*.md`).
6. ✅ Ambas imágenes base fijadas por tag + digest (`@sha256:...`), mismos
   digests que `user-service` (verificados como apropiados para este
   repo).
7. ✅ `docker build` sin error; `docker run` con las 13 env vars
   requeridas arranca sin panic (falla al conectar a dependencias externas
   inexistentes en este entorno, comportamiento esperado y documentado).
8. ✅ `docs/architecture.md` §"Despliegue" extendida (nota de imagen +
   nota TLS pública ya existente, intacta).

## Dudas / bloqueos

Ninguno. No fue necesario tocar `src/`/`tests/` — no se encontró ningún
bug al verificar el arranque del binario (el fallo observado es el
esperado: sin conectividad real a Google/Broker/ms-usuarios en este
entorno de verificación, `wiring` falla limpiamente sin panic).

Pendiente (fuera del alcance de esta sesión, protocolo del agente
implementador): un `reviewer` debe validar este trabajo antes de marcar la
feature 11 como `done` en `feature_list.json`.
