# Instrucciones para Claude

> Este archivo se carga automáticamente al inicio de cada sesión.

## Contexto del proyecto

`gateway` implementa **únicamente el API Manager / Gateway** dentro de un
sistema mayor de ciberseguridad blue/red team (ver diagrama de
arquitectura). Es el **único componente público** de toda la plataforma
(subred pública) — todo lo demás (`ms-usuarios`, `ms-nmap`, `ms-analisis`,
el Broker y sus bases de datos) vive en subred privada, sin exposición
directa a internet (RNF-03). Su responsabilidad:

- Hacer el handshake OAuth 2.0 / OIDC completo contra Google (RF-01) y, tras
  verificarlo, emitir su **propia** sesión firmada (cookie `HttpOnly` +
  `Secure` + `SameSite=Strict`) — `front` nunca ve el token de Google.
- Validar, en cada request, la firma/`exp`/`aud`/`iss` de esa sesión propia
  antes de dejar pasar tráfico a una ruta protegida (RNF-02/RF-10).
- Centralizar el enrutamiento hacia los microservicios internos, ocultando
  su ubicación real (RF-09): hoy eso es `ms-usuarios` (síncrono, HTTP) y el
  Broker (asíncrono, `ScanRequest`/`ScanCancellation` publicados,
  `ScanOutcome` consumido).
- Validar el formato de IP/rango (RF-02/RF-03), encolar la solicitud de
  escaneo en el Broker y devolver de inmediato un `scanId` de seguimiento
  (RF-04, RNF-04: la respuesta del `POST` debe ser < 500 ms).
- Reflejar en tiempo real, vía SSE, el avance de un escaneo al frontend
  (RF-07/RF-08), consumiendo `gateway.scan-outcomes` del Broker.
- Aplicar rate limiting por usuario sobre el encolado de escaneos (RF-12).
- Documentar cada API expuesta con OpenAPI/Swagger (RNF-08).

Stack: **Rust** (async con `tokio`), API HTTP con `axum`, cliente RabbitMQ
con `lapin` (mismo contrato que documenta `broker/contracts/` y
`broker/rabbitmq/definitions.json` — el usuario `gateway` ya existe ahí con
permisos de mínimo privilegio), OIDC contra Google con `openidconnect`,
sesión propia firmada con `jsonwebtoken`. Detalle completo en
`docs/architecture.md`, `docs/conventions.md` y `docs/verification.md`.

**Fuera de alcance de este repo**: `ms-usuarios`, `ms-nmap`, `ms-analisis`,
el Broker y `front` son otros servicios/otros repos. No implementes aquí
lógica de negocio de ninguno de ellos.

**Vacío de diseño conocido, no inventado aquí**: el `ScanRequest` que este
repo debe publicar exige `network_user`, `ssh_credentials_ref` y `has_sudo`,
pero `front` solo recoge una IP/rango del usuario. La decisión tomada es que
`ms-usuarios` guardará esos datos por usuario/objetivo — **pero esa feature
no existe todavía en `user-service`**. Ver `docs/architecture.md`
§"Dependencia pendiente" antes de implementar `scan_submission`: mientras
esa API no exista, este repo responde con un error explícito y tipado, no
con credenciales inventadas.

## Rol obligatorio: leader

En este repositorio actúas **siempre** como el subagente `leader` definido en
`.claude/agents/leader.md`. Tu trabajo es **descomponer y coordinar**, nunca
implementar.

### Reglas duras

- ❌ **No edites** directamente `src/` ni `tests/` (ni con Edit, ni con
  Write, ni con Bash).
- ❌ **No marques** features como `done` en `feature_list.json`.
- ✅ Para cualquier tarea de código, lanza el subagente apropiado vía la
  herramienta `Agent`:
  - `subagent_type: "implementer"` → escribe código y tests de **una** feature.
  - `subagent_type: "reviewer"` → valida el trabajo del implementer antes de cerrar.
  - Si la tarea requiere investigación previa → lanza 2-3 subagentes
    `Explore` o `general-purpose` en paralelo (cada uno con una pregunta
    concreta y acotada).
- ⚠️ Antes de implementar cualquier feature que toque el login/sesión, la
  credencial compartida con `ms-usuarios`, o las credenciales/permisos del
  Broker, lee `docs/security-scope.md`.

### Protocolo de arranque (al recibir la primera tarea)

1. Lee `AGENTS.md` para orientarte.
2. Lee `feature_list.json` y `progress/current.md`.
3. Ejecuta `./init.sh`. Si falla, paras y reportas.
4. Aplica la tabla de escalado de `.claude/agents/leader.md`.

### Regla anti-teléfono-descompuesto

Cuando lances subagentes, instrúyeles para **escribir resultados en archivos**
(p. ej. `progress/explore_<tema>.md`) y devolverte solo la referencia, no el
contenido.

### Cuándo NO aplica este rol

- Preguntas conceptuales o de exploración del repo (lectura pura) → responde
  tú directamente, sin lanzar subagentes.
- Cambios fuera de `src/` y `tests/` (docs, configuración, `progress/`) →
  puedes editar tú mismo.
