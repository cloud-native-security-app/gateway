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

Toda función pública de lógica pura (`domain`, validación de IP/rango,
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

- `broker`: contra el contenedor `rabbitmq:management` oficial levantado
  vía `testcontainers`, con la topología copiada literalmente de
  `broker/rabbitmq/definitions.json` (mismos exchanges/colas/permisos del
  usuario `gateway`) aplicada al arrancar el contenedor de test. Nunca
  contra el Broker de producción, nunca con un mock del protocolo AMQP.
- `usuarios_client`: contra un servidor HTTP de test (real, escuchando en
  un puerto — no una interceptación a nivel de módulo) que implementa el
  contrato documentado de `ms-usuarios`.
- `auth`: la validación de JWKS/ID token de Google se prueba contra un
  servidor HTTP de test que sirve un JWKS y tokens firmados con una clave
  de prueba (nunca contra el endpoint real de Google en el test suite) —
  la firma/expiración/audiencia se verifican con esa clave de laboratorio.
- `api`: tests end-to-end que levantan el servicio real sobre el contenedor
  RabbitMQ de test y el servidor de contrato de `ms-usuarios`, ejerciendo
  rutas HTTP reales (incluida la suscripción SSE).
- Todo test de esta categoría se marca `#[ignore = "requiere Docker"]` (ver
  `docs/conventions.md`), se ejecuta con `cargo test -- --ignored`, y
  requiere Docker disponible (local o en CI). Si falla por falta de Docker,
  se documenta como bloqueo en `progress/current.md` — no se reemplaza por
  un mock.

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
- ❌ Marcar la feature como `done` sin pasar `./init.sh`.

## Verificación final antes de cerrar

```bash
./init.sh           # debe terminar con [OK] Entorno listo
```

Si `./init.sh` está rojo, **no** marques nada como `done`. Anota el bloqueo
en `progress/current.md` y pon `"status": "blocked"` en `feature_list.json`.
