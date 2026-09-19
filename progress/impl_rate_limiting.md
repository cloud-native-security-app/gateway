# Implementación — feature 9: rate_limiting

## Archivos creados/modificados

- `src/config.rs`: nuevas variables de entorno requeridas
  `SCAN_SUBMISSION_RATE_LIMIT_MAX_REQUESTS` (u32) y
  `SCAN_SUBMISSION_RATE_LIMIT_WINDOW_SECS` (u64), campos correspondientes en
  `Config`, parseo con el mismo patrón de `ConfigError::InvalidNumber` que ya
  usan `HTTP_PORT`/`SESSION_TTL_SECS`. Tests: carga válida, cada var faltante
  produce `ConfigError::Missing`, valor no numérico de cada nueva var produce
  `ConfigError::InvalidNumber`, `Debug` no filtra nada (no son secretos, no
  aplica redacción).
- `src/api.rs`:
  - `ScanSubmissionRateLimiter`: limitador en memoria de ventana fija por
    `sub` (`HashMap<String, RateLimitWindow>` tras un `Mutex`), con
    `check_and_record(sub) -> bool`. Mismo patrón que `LoginStateStore`
    (`src/auth.rs`) y `ScanOwnershipRegistry` (mismo archivo): en memoria, no
    compartido entre instancias, documentado como limitación aceptada.
  - `RateLimitError`/`impl IntoResponse` (variante `Exceeded` -> `429` con
    mensaje explícito, `thiserror`).
  - `rate_limit_scan_submission`: middleware `axum::middleware::from_fn_with_state`
    que lee `Extension<Session>` (ya insertada por `auth::require_session`) y
    llama a `check_and_record(&session.sub)`.
  - `AppState::scan_submission_rate_limiter: Arc<ScanSubmissionRateLimiter>`
    (nuevo campo).
  - `protected_router`: el `MethodRouter` de `POST /api/scans` se construye
    aparte (`post(submit_scan).layer(middleware::from_fn_with_state(...))`)
    y solo después se le añade `.get(list_scan_history)` — así el rate
    limiter queda anidado únicamente en el método `POST` de esa ruta, no en
    `GET /api/scans` ni en el resto de rutas protegidas. Verificado leyendo
    el código fuente real de `axum` 0.7.9
    (`MethodRouter::layer`, `src/routing/method_routing.rs:963-989`): `.layer()`
    envuelve solo los métodos ya configurados en ese momento (`self.post`),
    dejando `self.get` (`None` todavía) sin tocar.
  - Unit tests (`#[cfg(test)] mod tests`, al final del archivo, lógica pura
    sin IO): umbral respetado, rechazo al superarlo, contadores
    independientes por usuario, reinicio tras expirar la ventana.
- `src/wiring.rs`: construye `scan_submission_rate_limiter` desde
  `config.scan_submission_rate_limit_max_requests`/`_window_secs` y lo añade
  al `AppState` real.
- `tests/rate_limiting.rs` (nuevo): 3 tests de integración end-to-end contra
  el router real (`app_router`), sin Docker:
  - `user_exceeding_the_threshold_receives_429_on_the_request_that_exceeds_it`:
    umbral 2, la 1ª y 2ª solicitud de un usuario responden `200`, la 3ª `429`.
  - `a_second_user_in_parallel_is_not_affected_by_another_users_limit`:
    umbral 1, el usuario A agota su cupo; en paralelo (`tokio::join!`), la
    2ª solicitud de A da `429` mientras la 1ª de B (sesión distinta) da `200`
    — contadores independientes.
  - `exceeding_the_limit_never_reaches_ms_usuarios_or_the_broker`: umbral 0
    con `ms-usuarios` inalcanzable y un doble de `ScanRequestPublisher` que
    hace `panic!` si se invoca — confirma que el `429` ocurre antes de
    cualquier llamada externa (si el orden de capas estuviera mal, este test
    fallaría por panic o por un status de error de red, no por `429`).
- Actualizados (solo para añadir el nuevo campo obligatorio de `AppState`,
  con un límite alto — 1000/60s — que no interfiere con sus propios
  escenarios): `tests/usuarios_profile_proxy.rs`, `tests/oidc_login.rs`,
  `tests/session_middleware_and_me.rs`, `tests/scan_outcome_relay.rs`,
  `tests/scan_history_and_cancellation.rs`, `tests/scan_submission.rs`.

## Decisión: limitador propio en memoria, no `tower_governor`

Se evaluó `tower_governor` (mencionado como ejemplo, no obligatorio, en el
criterio de aceptación). Antes de comprometerme a usarlo confirmé que
necesitaría implementar su trait `KeyExtractor` propio para sustituir la
clave por IP por defecto por la identidad de sesión, y coordinar
correctamente que ese extractor solo pueda ver la sesión ya validada
(después de `auth::require_session`) — es decir, la misma restricción de
orden de capas que ya tenía que resolver de todos modos. Añadir esa
dependencia y su superficie de API (bounds genéricos de `GovernorLayer`,
gestión de su propio store interno) no aportaba nada que el patrón ya usado
tres veces en este repo (`LoginStateStore`, `ScanOwnershipRegistry`) no
resolviera de forma más simple y ya familiar al resto del código. Se optó
por el limitador propio (`ScanSubmissionRateLimiter`), documentando en su
propio rustdoc la misma limitación conocida y aceptada de esos dos tipos
(en memoria, no compartido entre instancias, no sobrevive un reinicio).

## Orden de capas verificado

`protected_router` aplica el middleware de sesión (`require_session`) como
capa de todo el `Router` (se ejecuta antes de la fase de *routing*, ver
`Router::layer`), y el rate limiter como capa del `MethodRouter` de `POST
/api/scans` únicamente (se ejecuta después del *routing*, ya dentro del
despacho a ese método/ruta). Confirmado leyendo
`axum-0.7.9/src/routing/method_routing.rs` (`MethodRouter::layer` solo
envuelve los métodos ya registrados al momento de llamarlo) en el registro
local de `cargo` — no hay ambigüedad sobre si `GET /api/scans` quedaría
afectado (no lo está).

## Verificación de los 5 criterios de aceptación

1. **Middleware aplicado a `POST /api/scans`, clave = identidad de sesión**:
   confirmado por lectura de código (`rate_limit_scan_submission` usa
   `Extension<Session>.sub`, nunca la IP/`ConnectInfo`) y por el test
   `exceeding_the_limit_never_reaches_ms_usuarios_or_the_broker` (umbral 0
   rechaza toda solicitud sin importar origen de red).
2. **Umbral configurable vía `Config`, sin hardcode**: `grep -rn` confirma
   que `ScanSubmissionRateLimiter::new` solo se construye con valores de
   `Config` (`src/wiring.rs`) o de tests explícitos — ningún número mágico
   en `src/api.rs`. Tests de `config.rs` cubren carga/errores de las 2 vars
   nuevas.
3. **429 con mensaje explícito, sin tocar `ms-usuarios` ni el Broker**:
   `RateLimitError::Exceeded` -> `429` (`StatusCode::TOO_MANY_REQUESTS`) con
   mensaje descriptivo; test de integración con `ms-usuarios` inalcanzable y
   publicador que hace panic si se invoca, pasa (ver arriba).
4. **Contadores independientes por usuario**: unit test
   `rate_limiter_keeps_independent_counters_per_user` + integration test
   `a_second_user_in_parallel_is_not_affected_by_another_users_limit`.
5. **Tests de integración pedidos**: los 2 primeros tests de
   `tests/rate_limiting.rs` cubren exactamente el escenario descrito
   (usuario que excede -> `429` en la solicitud que lo supera; segundo
   usuario en paralelo -> sigue recibiendo `200`).

## Resultado de los comandos de verificación

- `cargo build`: **OK**, sin warnings.
- `cargo clippy --all-targets -- -D warnings`: **OK**, sin advertencias.
- `cargo fmt --check`: **OK** tras `cargo fmt` (formateó `tests/rate_limiting.rs`
  y el `use` de `tests/session_middleware_and_me.rs`).
- `cargo test` (sin `--ignored`): **OK**, 54 unit tests + todos los tests de
  integración no marcados `#[ignore]` en verde, incluidos los 3 nuevos de
  `tests/rate_limiting.rs` y ninguna regresión en las features 1-8.
- `cargo test -- --ignored` (Docker disponible en este entorno): **OK**, los
  3 tests que requieren `testcontainers`/RabbitMQ real
  (`scan_submission`, `scan_outcome_relay`, `scan_history_and_cancellation`)
  siguen en verde.
- `./init.sh`: **exit code 0**, 0 líneas `[FAIL]`, "Entorno listo."

## Dudas / bloqueos

Ninguno. No se tocó `src/` fuera de `config.rs`/`api.rs`/`wiring.rs`, ni
lógica de otras features (OpenAPI, containerization, ni el contrato
`ScanRequest`/`ScanCancellation`).
