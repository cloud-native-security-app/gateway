# Verificación — Cómo demostrar que el trabajo funciona

> Regla de oro: **el agente no dice "funciona", lo demuestra**.
> Toda feature termina con evidencia ejecutable, no con afirmaciones.

## Niveles de verificación

### Nivel 0 — Documentación de código (obligatorio)

```bash
cargo doc --no-deps
```

Todo ítem público sin rustdoc (`///`) es motivo de `CHANGES_REQUESTED` en
revisión, no solo un nice-to-have.

### Nivel 1 — Tests unitarios (obligatorio)

Toda función pública de lógica pura (`domain`, validación de IP única,
construcción/validación de la sesión firmada) tiene al menos un test que:

1. Cubre el camino feliz.
2. Cubre al menos un camino de error si la función puede fallar.

Comando:
```bash
cargo test
```

### Nivel 2 — Lints y formato (obligatorio)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Ningún warning de clippy se ignora en silencio; si es un falso positivo,
se documenta con `#[allow(...)]` y un comentario explicando por qué.

### Nivel 3 — Tests de integración (obligatorio para auth, usuarios_client, broker, api)

- `broker` (adaptadores `sns`/`sqs`): contra un contenedor
  `localstack/localstack:4.4` levantado vía `testcontainers`; cada test crea
  los topics, colas, suscripciones raw y la DLQ (con `RedrivePolicy`) que
  necesita (`tests/common/mod.rs`). Nunca contra AWS real, nunca con un
  mock del SDK de AWS.
- `usuarios_client`: contra un servidor HTTP de test (real, escuchando en
  un puerto — no una interceptación a nivel de módulo) que implementa el
  contrato documentado de `ms-usuarios`.
- `auth`: la validación de JWKS/ID token de Google se prueba contra un
  servidor HTTP de test que sirve un JWKS y tokens firmados con una clave
  de prueba (nunca contra el endpoint real de Google en el test suite) —
  la firma/expiración/audiencia se verifican con esa clave de laboratorio.
- `api`: tests end-to-end que levantan el servicio real sobre el contenedor
  LocalStack de test y el servidor de contrato de `ms-usuarios`, ejerciendo
  rutas HTTP reales (incluida la suscripción SSE).
- Todo test de esta categoría se marca `#[ignore = "requiere Docker"]` (ver
  `docs/conventions.md`), se ejecuta con `cargo test -- --ignored`, y
  requiere Docker disponible (local o en CI). Si falla por falta de Docker,
  se reporta como bloqueo en la descripción del cambio — no se reemplaza
  por un mock.

## Anti-patrones (no hacer)

- ❌ "Añadí el endpoint, debería funcionar." → falta test ejecutable contra
  el servicio real.
- ❌ Test que solo verifica el status code HTTP. → tiene que comprobar el
  contenido concreto del cuerpo de la respuesta.
- ❌ Probar `broker` contra el Broker de producción, o `usuarios_client`
  contra `user-service` de producción.
- ❌ Inventar el shape de una API que no existe todavía (ver
  `docs/architecture.md` §"Dependencia pendiente") en vez de documentar el
  bloqueo.
- ❌ Silenciar un warning de `clippy` con `#[allow(...)]` sin comentario.
- ❌ Dar una tarea por terminada sin pasar `make verify`.

## Verificación final antes de cerrar

```bash
make verify         # fmt + clippy + test + test --ignored + doc
make check          # igual, sin los tests que requieren Docker
```

Si `make verify` está rojo, **no** des la tarea por terminada. Documenta el
bloqueo (p. ej. Docker no disponible) en el documento de la tarea
(`odd/tasks/<feature>.md`) y en la descripción del cambio.
