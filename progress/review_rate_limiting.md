# Review — feature 9 (rate_limiting)

**Veredicto:** APPROVED

## Verificación ejecutada por el reviewer (no solo el informe del implementer)

- `cargo build`: OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings`: OK, sin advertencias.
- `cargo fmt --check`: OK, sin diferencias.
- `cargo test` (sin `--ignored`): OK — 54 unit tests + todos los tests de
  integración no-Docker en verde, incluidos los 3 nuevos de
  `tests/rate_limiting.rs`; sin regresión en las features 1-8
  (`oidc_login`, `scan_history_and_cancellation`, `scan_outcome_relay`,
  `scan_submission`, `session_middleware_and_me`, `usuarios_client`,
  `usuarios_profile_proxy`).
- `cargo test -- --ignored` (Docker disponible en este entorno): OK — los 3
  tests marcados `#[ignore = "requiere Docker"]`
  (`scan_history_and_cancellation`, `scan_outcome_relay`, `scan_submission`)
  siguen en verde.
- `./init.sh`: exit code 0, 0 líneas `[FAIL]`, "Entorno listo."

## Criterios de aceptación (feature 9, `feature_list.json`)

1. **Middleware de rate limiting aplicado a `POST /api/scans`, clave =
   identidad de sesión (no IP)** — **PASA**.
   `src/api.rs:259-270` (`rate_limit_scan_submission`) toma
   `Extension<Session>` y llama a `limiter.check_and_record(&session.sub)`;
   no hay ningún uso de `ConnectInfo`/IP en todo el archivo. Se aplica solo
   al método `POST` de `/api/scans` (`src/api.rs:353-364`,
   `protected_router`), anidado dentro de la capa de sesión que ya cubre
   todo el router protegido, así que se ejecuta después de
   `auth::require_session`. Verificado también con
   `tests/session_middleware_and_me.rs::enumerates_routes_and_verifies_which_carry_the_session_middleware`
   (sigue en verde, sin cambios en `ROUTES`).

2. **Umbral configurable vía `Config`, sin hardcode** — **PASA**.
   `src/config.rs` añade `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS` (u32) y
   `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS` (u64), con el mismo patrón de
   `required_string(...).parse().map_err(ConfigError::InvalidNumber)` que ya
   usan `HTTP_PORT`/`SESSION_TTL_SECS`. `src/wiring.rs:93-96` es el único
   sitio de `src/` (fuera de `#[cfg(test)]`) que construye
   `ScanSubmissionRateLimiter::new`, y lo hace con
   `config.scan_submission_rate_limit_max_requests`/`_window_secs`. Los
   únicos números literales pasados a `ScanSubmissionRateLimiter::new` están
   en `#[cfg(test)] mod tests` de `src/api.rs` y en los `spawn_gateway`/
   `spawn_gateway_with` de los archivos de `tests/` (confirmado con
   `grep -rn "ScanSubmissionRateLimiter::new"`).

3. **Exceder el límite responde 429 con mensaje explícito, sin publicar al
   Broker ni tocar `ms-usuarios`** — **PASA**.
   `RateLimitError::Exceeded` (`thiserror`) mapea a
   `StatusCode::TOO_MANY_REQUESTS` con mensaje explícito
   (`src/api.rs:228-245`). El chequeo ocurre en el middleware, **antes** de
   que `axum` invoque el handler `submit_scan` (que es quien llama a
   `resolve_scan_target`/`create_scan_history`/`publish_scan_request`): si
   `check_and_record` devuelve `false`, `next.run(request).await` nunca se
   ejecuta (`src/api.rs:264-269`). Confirmado además, no solo por lectura,
   por el test de integración
   `tests/rate_limiting.rs::exceeding_the_limit_never_reaches_ms_usuarios_or_the_broker`:
   umbral 0, `ms-usuarios` inalcanzable (puerto cerrado) y un
   `ScanRequestPublisher` doble que hace `panic!` si se invoca — el test
   pasa con `429`, así que si el orden de capas estuviera invertido habría
   fallado por pánico o por un status de error de red, no por `429`.

4. **Dos usuarios con sesiones válidas tienen contadores independientes** —
   **PASA**. `ScanSubmissionRateLimiter.entries: Mutex<HashMap<String,
   RateLimitWindow>>` usa el `sub` de la sesión como clave del mapa
   (`src/api.rs:177-225`) — no hay un contador global ni una clave
   compartida. Bajo concurrencia: `check_and_record` toma el `Mutex` una
   sola vez y hace lectura+decisión+incremento dentro de esa misma sección
   crítica (`src/api.rs:202-225`), así que no hay TOCTOU entre leer el
   contador y escribirlo — dos llamadas concurrentes (incluso del mismo
   `sub`) se serializan correctamente por el `Mutex` estándar. Unit test
   `rate_limiter_keeps_independent_counters_per_user` (`src/api.rs:1051-1064`)
   y test de integración `a_second_user_in_parallel_is_not_affected_by_another_users_limit`
   (con `tokio::join!` real) lo confirman.

5. **Tests de integración: usuario que excede recibe 429 en la solicitud que
   lo supera; segundo usuario en paralelo sigue con 200/202** — **PASA**.
   `tests/rate_limiting.rs` tiene exactamente estos dos escenarios
   (`user_exceeding_the_threshold_receives_429_on_the_request_that_exceeds_it`,
   `a_second_user_in_parallel_is_not_affected_by_another_users_limit`), más
   un tercero (`exceeding_the_limit_never_reaches_ms_usuarios_or_the_broker`)
   que cubre el criterio 3. Los tres corren contra el router real
   (`app_router`) sin Docker, con sesiones firmadas de laboratorio distintas
   por `sub` (`session_cookie_value_for`) — nunca por IP.

## Evaluación de la decisión de diseño: limitador propio vs `tower_governor`

El criterio de aceptación 1 menciona `tower_governor` como ejemplo ("p.
ej."), no como requisito duro — confirmado leyendo el texto literal en
`feature_list.json:133`. `docs/architecture.md` línea 68-70 sí lo nombra
como la decisión "ya tomada", pero ese mismo documento no impone una capa
adicional si el patrón ya usado en el repo resuelve el mismo requisito
(identidad de sesión como clave, umbral configurable, ventana por usuario)
sin ambigüedad. La justificación del implementer es razonable y verificable:

- `tower_governor` exigiría un `KeyExtractor` propio para reemplazar su
  clave por IP por defecto, y coordinar el mismo problema de orden de capas
  (debe ejecutarse después de `require_session` para poder leer la sesión)
  que el limitador propio ya resuelve de forma directa.
- El patrón elegido (`Mutex<HashMap<...>>` con limitación documentada de "en
  memoria, no compartido entre instancias") ya se usa dos veces en este
  mismo repo (`auth::LoginStateStore`, `ScanOwnershipRegistry`) — consistente
  con `docs/conventions.md` ("homogeneidad extrema").
- La implementación es correcta bajo concurrencia: una sola adquisición de
  `Mutex` por llamada, sin ventana de carrera entre verificar y contar.
- No se introduce una dependencia nueva a `Cargo.toml` sin necesidad
  concreta (alineado con `CHECKPOINTS.md` C3: "toda dependencia... está
  justificada").

No es una violación de `docs/architecture.md`: la línea 68-70 documenta una
intención de diseño, no una obligación irrenunciable, y el criterio de
aceptación correspondiente explícitamente la deja abierta. Se considera una
decisión de diseño aceptable y bien documentada (rustdoc de
`ScanSubmissionRateLimiter`, `progress/impl_rate_limiting.md`,
`progress/current.md`).

## Otros puntos verificados

- **Sin filtración de credenciales/sesión en logs o respuestas de error**:
  `RateLimitError::into_response` solo loggea `error = %self` (el mensaje
  fijo de `Exceeded`, sin `sub`/email/token) vía `tracing::debug!`
  (`src/api.rs:240-244`). Ningún log de esta feature incluye el `sub` de la
  sesión, el token de Google, la sesión firmada, la credencial de
  `ms-usuarios` ni la credencial AMQPS.
- **Nada de `unwrap()`/`expect()`/`panic!()` fuera de tests** en el código
  nuevo de `src/api.rs`, `src/config.rs`, `src/wiring.rs` (verificado con
  `grep`; los únicos `unwrap()`/`expect()` de `src/config.rs` están dentro
  de `#[cfg(test)] mod tests`; el `unwrap_or_else(|poison| poison.into_inner())`
  del `Mutex`/`RwLock` ya es el patrón preexistente del repo, no pánico).
- **Errores tipados con `thiserror`**: `RateLimitError` sigue el mismo
  patrón que el resto del archivo (`ScanSubmitError`, `ScanEventsError`,
  `ScanCancelError`).
- **Rustdoc**: `ScanSubmissionRateLimiter`, `check_and_record`,
  `rate_limit_scan_submission` y los nuevos campos de `Config`/`AppState`
  llevan `///` explicando propósito y motivo de diseño; `cargo doc --no-deps`
  (parte de `./init.sh`) genera sin warnings.
- **RF-10 (ninguna ruta protegida queda accesible sin el middleware de
  sesión)**: el rate limiter se añade como capa adicional del método `POST`
  de `/api/scans`, anidada *dentro* de la capa de `require_session` que ya
  envuelve todo `protected_router` — no la reemplaza ni la sortea. La tabla
  `ROUTES`/el test de enumeración de rutas no cambiaron y siguen en verde,
  así que ninguna ruta cambió su estado protegido/público por accidente.
- **Archivos de test modificados por el nuevo campo obligatorio de
  `AppState`** (`tests/usuarios_profile_proxy.rs`, `tests/oidc_login.rs`,
  `tests/session_middleware_and_me.rs`, `tests/scan_outcome_relay.rs`,
  `tests/scan_history_and_cancellation.rs`, `tests/scan_submission.rs`): el
  diff de cada uno es mínimo (un `use` nuevo + un campo
  `scan_submission_rate_limiter: Arc::new(ScanSubmissionRateLimiter::new(1000,
  Duration::from_secs(60)))` con umbral alto para no interferir con sus
  propios escenarios) — no se tocó lógica de otras features.

## Checkpoints relevantes (`CHECKPOINTS.md`)

- C2 (estado coherente): `feature_list.json` tiene exactamente una feature
  `in_progress` (id 9) — [x].
- C3 (arquitectura): sin módulos nuevos fuera de `config`/`api`/`wiring`; sin
  dependencia nueva en `Cargo.toml`; sin `unwrap`/`panic!` fuera de tests sin
  justificar; `cargo doc --no-deps` sin warnings; no se inventó ningún shape
  de API pendiente — [x].
- C4 (verificación real): tests de integración presentes y en verde,
  `cargo test` > 0 tests todos verdes, `cargo clippy -D warnings` limpio —
  [x].

## Conclusión

Los 5 criterios de aceptación de la feature 9 se cumplen, verificados tanto
por lectura de código como por ejecución real de `cargo build`/`clippy`/
`fmt --check`/`test`/`test -- --ignored`/`./init.sh`. La decisión de usar un
limitador propio en memoria en vez de `tower_governor` está justificada y es
consistente con el resto del repo, sin violar `docs/architecture.md` (el
criterio de aceptación deja la crate como ejemplo, no como obligación). No
se requieren correcciones.
