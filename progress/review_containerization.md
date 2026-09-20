# Review — feature 11 (containerization)

**Veredicto:** APPROVED

## Criterios de aceptación (feature_list.json, id=11)

1. **Dockerfile multi-stage en la raíz (builder Rust + runtime distroless/cc mínimo con binario + CA certs) — PASA.**
   `Dockerfile` tiene stage `builder` (`FROM rust:1.98-bookworm@sha256:82150a52...` línea con `AS builder`) que corre `cargo build --release` (dos veces: capa de cacheo de deps con `src/lib.rs`/`src/main.rs` placeholder, luego `COPY src ./src` + rebuild real) y stage runtime `FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79...`, que trae certificados CA de sistema.

2. **Imagen final sin toolchain ni código fuente — PASA.**
   El stage final solo tiene `COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway`; no hay `COPY src` ni `COPY Cargo.*` en ese stage. Verificado además que no hay shell: `docker run --rm --entrypoint sh gateway:review-check -c "echo hi"` → `exec: "sh": executable file not found in $PATH` (exit 127).

3. **Corre como usuario no-root — PASA.**
   `docker inspect gateway:review-check --format '{{.Config.User}}'` → `nonroot`. El Dockerfile fija `USER nonroot` explícitamente antes del `ENTRYPOINT`.

4. **Config vía env vars + README documenta las requeridas para `docker run` — PASA.**
   Confirmado leyendo `src/config.rs` directamente (no solo el informe del implementer): hay 14 constantes `ENV_*`. 13 son requeridas (`required_string`/`required_secret`, fallan con `ConfigError::Missing` si faltan): `HTTP_HOST`, `HTTP_PORT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `SESSION_SIGNING_KEY`, `SESSION_TTL_SECS`, `BROKER_AMQPS_URL`, `BROKER_VHOST`, `MS_USUARIOS_BASE_URL`, `MS_USUARIOS_SHARED_SECRET`, `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS`, `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS` — todas también están en `ALL_REQUIRED_VARS` en los tests de `config.rs`. La única con default es `GOOGLE_OIDC_ISSUER_URL` (`optional_string_with_default`, default `https://accounts.google.com`, ausente de `ALL_REQUIRED_VARS`). La tabla de `README.md` §"Despliegue (Docker)" lista las 14, con la columna "Requerida" correcta para cada una. El ejemplo de `docker run` incluye las 13 requeridas con valores sintéticos (`change-me`, `*.internal`) — ninguna credencial real, conforme a `docs/security-scope.md`.

5. **`.dockerignore` excluye al menos `target/`, `.git/`, `.claude/`, `progress/`, `docs/` — PASA.**
   El archivo excluye exactamente esos cinco más `.gitignore`, `tests/`, `rabbitmq/`, `*.md`, `Dockerfile`, `.dockerignore`. Verificado con `grep -rn "rabbitmq/" src/ tests/` que las fixtures de `rabbitmq/` (definitions.json, TLS, conf) solo las usan `tests/scan_submission.rs` y `tests/scan_history_and_cancellation.rs` (vía testcontainers), nunca `src/` — excluirlas del contexto de build de producción es correcto y no rompe `cargo build --release` (confirmado con build real, ver criterio 7). No excluye `src/`, `Cargo.toml` ni `Cargo.lock`.

6. **Imágenes base fijadas por tag + digest — PASA.**
   `rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922` y `gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`. Ninguna usa `latest` ni un tag flotante sin digest.

7. **`docker build` sin error; `docker run` arranca sin panic — PASA (verificado independientemente, no solo el informe del implementer).**
   - `docker build -t gateway:review-check .` (con caché reutilizado del implementer) → éxito en 2.8s.
   - Repetido con `docker build --no-cache -t gateway:review-check .` (build 100% desde cero, sin depender de caché ajena) → éxito en 1m46s, compila las ~80 dependencias + el crate `gateway` dos veces (capa de cacheo + capa real), termina sin error.
   - `docker images gateway:review-check` → 51.7MB disco / 13.4MB contenido — coincide con lo reportado por el implementer.
   - `timeout 6 docker run --rm -e HTTP_HOST=0.0.0.0 -e HTTP_PORT=8080 -e GOOGLE_CLIENT_ID=lab-client-id -e GOOGLE_CLIENT_SECRET=lab-only-not-a-real-secret -e GOOGLE_REDIRECT_URI=https://gateway.lab/auth/callback -e SESSION_SIGNING_KEY=lab-only-not-a-real-secret -e SESSION_TTL_SECS=3600 -e BROKER_AMQPS_URL=amqps://gateway:lab-only-not-a-real-secret@broker.lab:5671 -e BROKER_VHOST=security-app -e MS_USUARIOS_BASE_URL=http://ms-usuarios.lab -e MS_USUARIOS_SHARED_SECRET=lab-only-not-a-real-secret -e SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS=5 -e SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS=60 -p 18081:8080 gateway:review-check` (todos los valores sintéticos de laboratorio, ninguna credencial real) → log único `ERROR gateway: el proceso de gateway terminó con un error fatal error=no se pudo completar la inicialización del servicio`, exit code 1, **sin panic, sin stack trace, sin ninguna credencial en el log** (esperado: no hay Google/Broker/ms-usuarios reales en este entorno).
   - Adicional (no exigido pero relevante): `docker run --rm gateway:review-check` sin ninguna env var → `ERROR ... error=no se pudo cargar la configuración`, exit 1, tampoco panic — confirma que la ruta de `ConfigError::Missing` tampoco produce pánico ni fuga.
   - Limpieza: `docker rmi gateway:review-check` ejecutado al terminar; `docker ps -a` sin contenedores huérfanos de `gateway`.

8. **`docs/architecture.md` §Despliegue extendida — PASA.**
   `git diff docs/architecture.md` confirma que el párrafo original sobre terminación TLS pública ("Gateway sirve HTTP plano dentro de la subred; la terminación TLS pública (RNF-01) se asume hecha por un balanceador/ingress...") **sigue presente sin cambios**, y se añadió un párrafo nuevo después explicando la imagen (multi-stage, qué incluye/excluye, y que el binario es cliente TLS saliente hacia Google/`ms-usuarios`/Broker) sin duplicar ni contradecir la nota TLS ya existente.

## Otras verificaciones

- **`docs/security-scope.md`:** ningún valor usado en la verificación de `docker run` (ni la mía ni la del informe del implementer) es una credencial real — todos son `lab-*`, `change-me`, `*.lab`, `*.internal`. Ningún log de la verificación contiene `GOOGLE_CLIENT_SECRET`, `SESSION_SIGNING_KEY`, `BROKER_AMQPS_URL` ni `MS_USUARIOS_SHARED_SECRET` en texto plano en la salida — solo el mensaje de error tipado genérico.
- **`docs/conventions.md` (comentarios explican el *por qué*, no el *qué*):** los comentarios del `Dockerfile` explican decisiones (por qué se fija por digest, por qué no hay stage de sqlx/migraciones a diferencia de `user-service`, por qué `cargo build --release` sin `--bin` produce igual el binario `gateway`, por qué `ca-certificates` es necesario pese a no haber servidor TLS propio) en vez de narrar literalmente cada instrucción — cumple el estándar de "por qué no obvio".
- **RF-10 / rutas protegidas:** esta feature no toca `src/` ni `tests/` (`git diff --stat -- src/ tests/` vacío) — no hay riesgo de haber destapado una ruta protegida.
- **`./init.sh` completo (regresión features 1-10):** ejecutado dos veces de forma independiente, exit code 0 ambas veces. Todas las secciones `[OK]`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` sin warnings, tests unitarios (54 passed), tests de integración con Docker vía testcontainers (`scan_history_and_cancellation`, `scan_outcome_relay`, `scan_submission`, todos contra RabbitMQ real, ~6s cada uno — consistente con testcontainers real, no un mock), `cargo doc` sin warnings. Ninguna regresión.

## Checkpoints (`CHECKPOINTS.md`)

- **C1** — [x] Existen los 4 archivos base y los 4 docs; `./init.sh` exit code 0.
- **C2** — [x] Solo la feature 11 está `in_progress` (`grep -c` confirma 1 `in_progress`, 10 `done`, 0 `pending` = 11 total); toda feature `done` tiene tests que pasan (confirmado por `./init.sh`); `progress/current.md` describe la sesión activa, sin basura de sesiones previas.
- **C3** — [x] Esta feature no modifica `src/`/`tests/`, por lo que no introduce módulos fuera de lo previsto en `docs/architecture.md`, ni dependencias nuevas en `Cargo.toml`, ni `unwrap`/`panic!`/`println!` nuevos; `cargo doc --no-deps` sin warnings; no se inventó ningún shape de API pendiente (no aplica a esta feature).
- **C4** — [x] Los tests de `broker`/`usuarios_client`/`api` siguen corriendo contra RabbitMQ real vía `testcontainers` (verificado en la salida de `./init.sh`, tiempos ~6s por test consistentes con levantar un contenedor real); `cargo test` > 0 tests, todos verdes; `cargo clippy --all-targets -- -D warnings` sin advertencias.
- **C5** — [x] No hay archivos sin trackear sospechosos: solo `Dockerfile`, `.dockerignore`, `progress/impl_containerization.md` (todos legítimos de esta feature); `progress/history.md` aún no tiene entrada de la feature 11 — correcto, esa entrada la añade el `leader` al cerrar la sesión tras esta revisión, no antes; el estado de la feature 11 en `feature_list.json` sigue en `in_progress` (correcto: el `reviewer` no marca `done`, eso lo hace el `leader` tras leer este veredicto).

## Cambios requeridos

Ninguno.
