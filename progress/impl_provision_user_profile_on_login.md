# Implementación — feature 17: provision_user_profile_on_login

## Archivos modificados

- `src/api.rs`:
  - Nuevo enum `CallbackError` (`thiserror`, `#[error(transparent)]` sobre
    `AuthError` y `UsuariosClientError`, mismo patrón que `ScanSubmitError`),
    con su `impl IntoResponse` delegando en el `IntoResponse` ya existente de
    cada variante (sin inventar un mapeo HTTP nuevo).
  - `fn callback` cambia su firma de `Result<(CookieJar, Response), AuthError>`
    a `Result<(CookieJar, Response), CallbackError>`.
  - Inmediatamente después de construir `Session` y antes de `issue_session_token`/
    emitir la cookie, se llama a
    `state.usuarios_client.upsert_profile(&session, &serde_json::json!({ "display_name": session.name }))`.
    Un fallo se propaga con `?` (se convierte a `CallbackError::Usuarios` vía
    `#[from]`), sin llegar a issuar cookie ni `302`.
  - `#[utoipa::path(...)]` de `/auth/callback` actualizado: se agregan las
    respuestas `502`/`504` (fallo al garantizar el perfil en `ms-usuarios`);
    el `302` del camino feliz no cambia de status, solo se amplía su
    descripción.
  - No se tocó `usuarios_client.rs`: se reutiliza `UsuariosClient::upsert_profile`
    y `UserProfile` (`serde_json::Value`) ya existentes.

- `tests/oidc_login.rs`:
  - `spawn_gateway` ahora recibe `usuarios_base_url: &str` (antes apuntaba
    siempre a una URL inválida nunca contactada). Se agregó la constante
    `NEVER_CONTACTED_USUARIOS_BASE_URL` para los tests que fallan/terminan
    antes de llegar a `upsert_profile` (login, callbacks rechazados antes de
    construir sesión, logout).
  - Nuevo stub `spawn_usuarios_upsert_stub(fail: bool)`: servidor HTTP real
    en un puerto efímero que implementa `PUT /users/me`, captura el header
    `X-Forwarded-User` y el `display_name` del body, y responde `200` o
    `500` según `fail`.
  - `callback_with_valid_id_token_creates_session` y
    `callback_success_redirect_ignores_extra_query_params` ahora usan el
    stub en modo feliz (antes no ejercían `usuarios_client`; con el fix, si
    seguían apuntando a la URL inválida, habrían fallado con `504`).
  - 2 tests nuevos:
    - `callback_success_calls_upsert_profile_before_redirecting`: verifica
      que el `302` + `Set-Cookie` solo ocurren tras un `PUT /users/me`
      exitoso, con el header de identidad (`sub`/`email`) y
      `display_name == "Test User"` (el `name` del ID token, no un valor de
      la request de callback).
    - `callback_when_usuarios_upsert_fails_does_not_create_session_or_redirect`:
      con el stub respondiendo `500`, verifica `502`/`504` (en la práctica
      `502`, `UnexpectedResponse`), ausencia de `Set-Cookie` y de `Location`,
      y que el cuerpo del error no contiene la URL interna del stub.

- `docs/security-scope.md`: nueva viñeta en "Identidad y sesión" que
  documenta la llamada nueva desde el callback, reafirmando que
  `display_name` sale siempre de `session.name` (identidad ya verificada),
  nunca de un input sin verificar, y que un fallo de esa llamada bloquea la
  emisión de la cookie/redirect.

## Verificación de los 9 criterios de aceptación

1. **Llamada a `upsert_profile` antes de la cookie/redirect**: confirmado
   leyendo `fn callback` — la llamada está entre la construcción de
   `Session` y `auth::issue_session_token`/`session_cookie`/`redirect_found`.
2. **Body mínimo con `session.name`**: `serde_json::json!({ "display_name": session.name })`,
   usando el campo ya verificado de `Session`, nunca `params`/query/body del
   callback. Verificado también por el test
   `callback_success_calls_upsert_profile_before_redirecting` (asserts
   `display_name == "Test User"`, el `name` firmado en el ID token de
   prueba).
3. **Sin tipos/endpoints nuevos en `usuarios_client.rs`**: `git diff --stat`
   confirma que ese archivo no fue tocado; se reutiliza
   `UsuariosClient::upsert_profile`/`UserProfile` existentes.
4. **Fallo de `upsert_profile` bloquea cookie/302**: el `?` propaga el error
   antes de `issue_session_token`; verificado por el test
   `callback_when_usuarios_upsert_fails_does_not_create_session_or_redirect`
   (sin `Set-Cookie`, sin `Location`).
5. **Camino feliz sin cambios observables**: `callback_with_valid_id_token_creates_session`
   (actualizado para usar el stub feliz) sigue verificando `302` a
   `TEST_FRONT_BASE_URL` con la misma cookie `HttpOnly`/`Secure`/`SameSite=Strict`
   firmada correctamente — pasa en verde.
6. **Logins repetidos (`ON CONFLICT`)**: no se tocó `ms-usuarios`; se confía
   en el comportamiento ya existente ahí, tal como indica el criterio. No se
   verificó contra el repo hermano (fuera de alcance).
7. **Tests de integración nuevos**: los 2 tests descritos arriba, ambos
   verdes (`cargo test --test oidc_login`: 12 tests, 12 ok).
8. **`docs/security-scope.md` actualizado**: viñeta agregada en "Identidad y
   sesión" (ver arriba).
9. **Comandos de verificación**: todos en verde (ver abajo).

## Resultado de comandos de verificación

- `cargo build`: OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings`: OK, sin advertencias.
- `cargo fmt --check`: OK, sin diferencias (tras `cargo fmt`).
- `cargo test` (sin `--ignored`): `61 + 4 + 7 + 12 + 2 + 3 + 4 + 2 + 3 + 8 + 8 + 3` tests,
  todos `ok` (incluye los 12 de `tests/oidc_login.rs`, con los 2 nuevos).
- `cargo test -- --ignored` (Docker disponible en esta sesión): los 3 tests
  marcados `#[ignore = "requiere Docker"]` (`scan_submission`,
  `scan_outcome_relay`, `scan_history_and_cancellation`) pasan en verde.
- `./init.sh`: termina con `[OK] Entorno listo.` (fmt, clippy, tests sin
  Docker, tests con Docker, `cargo doc`, todo verde).

## Dudas / bloqueos

Ninguno. No se tocó ninguna otra feature ni archivo fuera del scope de la
17. `feature_list.json` sigue con la 17 en `in_progress` (no la marco `done`
yo mismo, corresponde al reviewer/leader tras su veredicto).
