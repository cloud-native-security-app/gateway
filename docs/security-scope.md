# Alcance de seguridad y autorización

> `gateway` es el **único componente público** de toda la plataforma y el
> punto donde convergen todas las credenciales: el token de Google, la
> sesión propia de cada usuario, la credencial de servicio hacia
> `ms-usuarios`, y la credencial AMQPS del Broker (que a su vez transporta
> `ssh_credentials_ref`, una credencial SSH real — ver
> `broker/docs/security-scope.md`). Un error aquí compromete todo lo demás.
> Este documento define los límites duros que aplican tanto al desarrollo
> (tests, ejemplos, datos de prueba) como al diseño del propio servicio.

## Identidad y sesión

- El ID token de Google se valida **una sola vez**, durante el callback de
  login (`openidconnect`: firma vía JWKS, `aud` = client id de este
  Gateway, `iss` = `accounts.google.com`/`https://accounts.google.com`,
  `exp` no vencido). Tras extraer la identidad (`sub`, `email`, nombre), el
  token se descarta — **nunca** se persiste, se loggea, ni se reenvía a
  ningún otro servicio.
- La sesión propia de Gateway (JWT firmado con `jsonwebtoken`) es lo único
  que viaja de vuelta al navegador, como cookie `HttpOnly` + `Secure` +
  `SameSite=Strict`. Su clave de firma vive en `Config` (variable de
  entorno), nunca hardcodeada, y **nunca** se expone en un log ni en un
  mensaje de error.
- Cada request a una ruta protegida valida esa sesión propia (firma, `exp`,
  `aud`, `iss` — RNF-02) antes de ejecutar cualquier lógica de negocio. Una
  sesión inválida/expirada es `401`, nunca un intento de "renovar
  silenciosamente" sin un flujo explícito.
- Un `logout` invalida la sesión del lado del navegador (borra la cookie);
  si en el futuro se necesita invalidación server-side (revocación antes de
  `exp`), es una feature nueva a discutir, no se asume aquí.

## Comunicación con `ms-usuarios`

- Cada llamada a `ms-usuarios` reenvía la identidad ya verificada (header
  de identidad, mismo contrato que exige
  `user-service/docs/security-scope.md`) **y** la credencial de servicio
  `GATEWAY_SHARED_SECRET` — nunca la sesión JWT completa de Gateway, nunca
  el token de Google.
- Esa credencial de servicio se lee de `Config` (variable de entorno) y
  nunca se loggea, ni en éxito ni en error.
- Este repo **no** reimplementa la autorización a nivel de fila que ya hace
  `ms-usuarios` (un usuario solo ve su propio perfil/histórico/auditoría) —
  confía en que `ms-usuarios` la aplica, pero tampoco reenvía un
  identificador de usuario que no sea el de la sesión ya verificada.

## Comunicación con el Broker

- La credencial AMQPS del usuario RabbitMQ `gateway` (definida en
  `broker/rabbitmq/definitions.json`, mínimo privilegio: solo `write` en
  `scan.requests`/`scan.cancellations`, solo `read` en
  `gateway.scan-outcomes`) se lee de `Config` — nunca hardcodeada, nunca
  loggeada.
- Toda conexión al Broker usa AMQPS (TLS), nunca el puerto AMQP en claro
  que `broker/docker-compose.yml` documenta como "solo depuración local".
- El cuerpo completo de un `ScanRequest` (que lleva `ssh_credentials_ref`,
  una credencial SSH real) **nunca** se loggea de forma persistente a
  stdout/stderr — mismo límite que ya documentan `broker/` y
  `nmap-service/` para ese mismo campo. Para depuración puntual en
  desarrollo, usar siempre valores de laboratorio, nunca una credencial
  real.

## Origen de `network_user`/`ssh_credentials_ref`/`has_sudo`

- Ver `docs/architecture.md` §"Dependencia pendiente": estos 3 campos deben
  obtenerse de `ms-usuarios`, cuya API para esto **todavía no existe**.
- Mientras no exista, este repo **nunca** genera, adivina, ni usa un valor
  por defecto/de ejemplo para `ssh_credentials_ref` en una ruta que un
  usuario real pueda alcanzar — eso equivaldría a escanear con una
  credencial que no le pertenece al usuario que la solicitó. El único lugar
  donde puede aparecer un valor de laboratorio es en tests, explícitamente
  marcado como tal (p. ej. `"lab-only-not-a-real-secret"`, mismo patrón que
  usan `broker/` y `nmap-service/`).

## Rate limiting y superficie pública

- Gateway es la única superficie de la plataforma alcanzable desde
  internet (RNF-03) — toda ruta que no sea estrictamente pública
  (`/auth/login`, `/auth/callback`, salud) exige sesión válida.
- El rate limiting por usuario (RF-12) sobre el encolado de escaneos usa la
  identidad de la sesión como clave, no la IP — un usuario detrás de un
  NAT/proxy compartido no debe poder saturar el límite de otro, ni evadir
  el propio cambiando de red.
- Ninguna ruta de este repo debe exponer una URL, puerto o credencial
  interna (`ms-usuarios`, Broker, `ms-nmap`) en una respuesta de error hacia
  el cliente — un error interno se traduce a un mensaje genérico hacia
  `front`, con el detalle real solo en logs del lado del servidor (sin
  credenciales).

## Desarrollo y tests

- Ningún test de este repo llama al endpoint real de Google ni a un
  `user-service`/Broker de producción — todos usan servidores/contenedores
  de laboratorio (ver `docs/verification.md`).
- Ninguna identidad de Google, credencial de servicio, o credencial AMQPS
  real aparece en fixtures, ejemplos o código de este repo — solo valores
  sintéticos de laboratorio.

## Si algo no está claro

Si una feature de `feature_list.json` roza alguno de estos límites y no está
claro cómo proceder, el agente **para y pregunta al usuario** en vez de
asumir qué está autorizado — igual que cualquier otro bloqueo, se documenta
en `progress/current.md`.
