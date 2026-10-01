# Review — feature 17 (provision_user_profile_on_login)

**Veredicto:** APPROVED

## Criterios de aceptación (feature_list.json id=17)

1. **Llamada antes de cookie/redirect** — PASA. `src/api.rs`, `fn callback`: el `await?` a
   `state.usuarios_client.upsert_profile(&session, &serde_json::json!({ "display_name": session.name }))`
   está inmediatamente después de construir `let session = Session { ... }` y antes de
   `auth::issue_session_token`/`session_cookie`/`redirect_found` (línea ~1373-1382 en el diff,
   bloque comentado "Feature `provision_user_profile_on_login`").

2. **Body = `{"display_name": session.name}`, nunca de query/body del callback** — PASA.
   Verificado por lectura directa del código y por el test
   `callback_success_calls_upsert_profile_before_redirecting`, que firma un ID token con
   `name: "Test User"` y confirma `call.display_name == Some("Test User".to_string())`, nunca un
   valor tomado de `CallbackParams`/query string. `CallbackParams` solo tiene `code`/`state`, no
   hay forma de que un valor de ahí llegara a `display_name`.

3. **Sin tipos/endpoints nuevos en `usuarios_client.rs`** — PASA. `git diff --stat` confirma que
   `src/usuarios_client.rs` no aparece en el diff. Se reutiliza
   `UsuariosClient::upsert_profile(&self, identity: &Session, profile: &UserProfile)` y
   `type UserProfile = serde_json::Value`, ya existentes (líneas 96 y 382 de ese archivo),
   exactamente como ya los usa el proxy de perfil.

4. **Fallo de `upsert_profile` bloquea cookie/302** — PASA. El `.await?` propaga el error vía el
   nuevo `CallbackError::Usuarios(#[from] UsuariosClientError)` antes de llegar a
   `issue_session_token`. Confirmado también por el test
   `callback_when_usuarios_upsert_fails_does_not_create_session_or_redirect`: con el stub
   respondiendo 500, la respuesta no trae `Set-Cookie` ni `Location`.

5. **Camino feliz sin cambios observables** — PASA. `callback_with_valid_id_token_creates_session`
   y `callback_success_redirect_ignores_extra_query_params` (ya existentes, actualizados para
   apuntar al stub feliz) siguen verificando 302 a `TEST_FRONT_BASE_URL` con la misma cookie
   `HttpOnly`/`Secure`/`SameSite=Strict`. Ambos en verde.

6. **Logins repetidos (`ON CONFLICT`)** — N/A de confianza, no se tocó `ms-usuarios`. Correcto
   según el propio criterio ("este fix no toca ms-usuarios").

7. **Tests nuevos en `tests/oidc_login.rs`** — PASA.
   - `callback_success_calls_upsert_profile_before_redirecting`: verifica `PUT /users/me` con el
     header `FORWARDED_USER_HEADER_NAME` (decodificado, `sub`/`email` correctos) y
     `display_name == "Test User"` antes del 302+cookie.
   - `callback_when_usuarios_upsert_fails_does_not_create_session_or_redirect`: con el stub en
     modo `fail`, responde 502/504 (en la práctica 502 vía `UnexpectedResponse`), sin
     `Set-Cookie`, sin `Location`, y el cuerpo de error no contiene la URL interna del stub
     (`!body.contains(&usuarios_base_url) && !body.contains("127.0.0.1")`).
   - Ambos tests ejecutados y en verde (`cargo test`, ver evidencia abajo). Los tests existentes
     que no ejercen `upsert_profile` (login, callbacks rechazados antes de construir sesión,
     logout) se mantienen apuntando a `NEVER_CONTACTED_USUARIOS_BASE_URL`, correctamente
     excluidos de necesitar el stub.

8. **`docs/security-scope.md` actualizado** — PASA. Nueva viñeta en "Identidad y sesión" que
   documenta la llamada desde el callback, reafirma que `display_name` sale siempre de
   `session.name` (identidad ya verificada) y que un fallo bloquea cookie/302. No introduce
   ninguna credencial nueva ni cambia el resto del documento.

9. **Comandos de verificación en verde** — PASA, verificado de forma independiente (no solo
   confiando en el informe del implementer):
   - `cargo build`: compila sin warnings.
   - `cargo clippy --all-targets -- -D warnings`: sin advertencias.
   - `cargo fmt --check`: sin diferencias.
   - `cargo test` (sin `--ignored`): 61+0+4+7+12+2+3+4+2+3+8+8+3 tests, todos `ok` (incluye los
     12 de `tests/oidc_login.rs` con los 2 nuevos, y los 2 de `tests/openapi_docs.rs` sin tocar).
   - `cargo test -- --ignored` (Docker disponible en esta sesión): los 3 tests marcados
     `#[ignore = "requiere Docker"]` (`scan_submission`, `scan_outcome_relay`,
     `scan_history_and_cancellation`) pasan en verde — confirma que el fix no rompió nada de
     las features 1-16.
   - `./init.sh`: termina con `[OK] Entorno listo.` (fmt, clippy, tests sin Docker, tests con
     Docker, `cargo doc`, todo verde).

## Verificaciones adicionales del revisor

- **`tests/openapi_docs.rs` (anti-drift)**: pasa sin cambios manuales suyos a pesar de que la
  anotación `#[utoipa::path(...)]` de `/auth/callback` cambió de shape (se agregaron las
  respuestas 502/504) — confirma que la feature `openapi_docs` sigue correctamente derivada del
  código y no quedó documentación desactualizada en silencio.
- **`IntoResponse` para `CallbackError`**: delega en el `IntoResponse` ya existente de
  `AuthError`/`UsuariosClientError`, sin inventar un mapeo HTTP nuevo ni un campo adicional en el
  cuerpo de error. `UsuariosClientError::into_response` usa `(status, self.to_string())`, cuyo
  mensaje (`#[error("...")]`) nunca incluye la URL interna de `ms-usuarios` ni ninguna credencial.
- **Alcance del diff**: `git diff --stat` confirma que solo se tocaron `docs/security-scope.md`,
  `feature_list.json`, `progress/current.md`, `src/api.rs` y `tests/oidc_login.rs`. No se tocó
  `usuarios_client.rs` ni ningún archivo de otro repo (`ms-usuarios`, `front`, `broker`).
  `feature_list.json` sigue correctamente con la 17 en `in_progress` (el implementer no se
  auto-aprobó).
- **Ruta protegida / RF-10**: esta feature no agrega ni modifica rutas protegidas; `/auth/callback`
  sigue pública, sin cambios de superficie expuesta por el middleware de sesión.
- **Filtrado de credenciales**: no se detectó ningún log, mensaje de error o respuesta HTTP que
  filtre el token de Google, la sesión firmada, la credencial de `ms-usuarios` o la credencial
  AMQPS. El único dato nuevo que viaja (`display_name`) es información no sensible ya presente en
  la sesión del propio usuario.

## Checkpoints relevantes (CHECKPOINTS.md)

- C2 (estado coherente): [x] — una sola feature `in_progress` (17); `progress/current.md`
  describe la sesión activa.
- C3 (arquitectura): [x] — no se tocaron módulos fuera de lo previsto; no se inventó ningún shape
  de API pendiente; sin `println!`/`dbg!`/`unwrap()` nuevos fuera de tests.
- C4 (verificación real): [x] — `cargo test` > 0 y todos verdes; `cargo clippy -D warnings` limpio.
- C1/C5: sin cambios relevantes a esta feature (no evaluados exhaustivamente aquí, fuera del
  alcance de esta revisión puntual).

## Veredicto final

**APROBADO.** Los 9 criterios de aceptación de la feature 17 se cumplen, verificados de forma
independiente (código leído línea por línea + comandos ejecutados por el revisor, no solo el
informe del implementer). `cargo build`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, `cargo test`, `cargo test -- --ignored` (con Docker) y `./init.sh` terminan en
verde. No hay fuga de credenciales ni de URLs internas, no se expande el alcance a otros repos, y
el camino feliz de `post_login_redirect` (feature ya `done`) queda intacto.
