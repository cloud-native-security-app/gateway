# Implementación — feature 5: `usuarios_profile_proxy`

## Archivos creados/modificados

- `Cargo.toml`: promovido `reqwest` de `dev-dependencies` a `dependencies`
  (mismas features `default-features = false, features = ["rustls-tls"]`,
  más `"json"` — ver decisión de diseño abajo). Eliminado el duplicado en
  `dev-dependencies` (ya no hace falta, una dependencia normal está
  disponible también en tests).
- `src/usuarios_client.rs` (antes vacío): implementación completa —
  `UsuariosClient::{new, get_profile, upsert_profile}`,
  `UsuariosClientError` (`thiserror`), `UserProfile`, constantes de header
  `IDENTITY_HEADER_NAME`/`SERVICE_SECRET_HEADER_NAME`, tests unitarios.
- `src/api.rs`: campo `AppState::usuarios_client: Arc<UsuariosClient>`, ruta
  `GET /api/profile` (protegida) en `protected_router` + `.with_state(state)`
  (necesario porque el handler `profile` ya usa `State<AppState>`, cosa que
  `me` no hacía), handler `profile`, entrada en la tabla `ROUTES`,
  `impl IntoResponse for UsuariosClientError`.
- `tests/usuarios_client.rs` (nuevo): tests de integración directos contra
  un stub HTTP real de `ms-usuarios` en un puerto efímero.
- `tests/usuarios_profile_proxy.rs` (nuevo): tests de integración
  extremo a extremo de `GET /api/profile` sobre el router real de
  `gateway::api::app_router`.
- `tests/oidc_login.rs` y `tests/session_middleware_and_me.rs`: actualizados
  solo para añadir el nuevo campo obligatorio `usuarios_client` al construir
  `AppState` (un `UsuariosClient` de laboratorio apuntando a una URL que esos
  tests nunca contactan). No se tocó ninguna otra lógica de esos tests ni de
  las features 3/4.

## Decisiones de diseño a confirmar (contrato de `ms-usuarios` no disponible en este checkout)

`user-service/docs/architecture.md` y `user-service/docs/security-scope.md`
(donde vive el contrato real) no existen en este checkout. Siguiendo la
instrucción explícita de la tarea, documento aquí las suposiciones tomadas
en vez de inventar el contrato "a ciegas":

1. **Header de identidad**: `X-Gateway-Identity`, con valor JSON
   `{"sub": "<sub verificado>", "email": "<email verificado>"}`. Se eligió
   JSON en un único header (no dos headers separados) para que quede
   explícito y fácil de extender si `ms-usuarios` necesita más campos de
   identidad en el futuro, sin cambiar el nombre del header. **Nunca**
   incluye `name` (no es dato de autorización) ni ningún campo del JWT de
   sesión completo.
2. **Header de credencial de servicio**: `X-Gateway-Service-Secret`, con el
   valor crudo de `MS_USUARIOS_SHARED_SECRET` (vía `SecretString::expose_secret`,
   solo en el momento de setear el header — nunca se loggea, nunca aparece
   en un `Debug`/error).
3. **Shape del perfil**: en vez de inventar campos concretos (nombre,
   organización, etc.) que no están documentados en ningún lado de este
   repo, `UsuariosClient` trata el perfil como JSON opaco
   (`UserProfile = serde_json::Value`): lo reenvía tal cual llega de
   `ms-usuarios` en `get_profile`, y reenvía tal cual el cuerpo dado en
   `upsert_profile`. Esto respeta al pie de la letra
   `docs/architecture.md` §"Qué NO hacer" ("no inventar el shape de la API
   de `ms-usuarios`") sin dejar de implementar una feature funcional y
   testeada contra el contrato asumido (`GET`/`PUT /users/me`).
4. **`reqwest` con features `rustls-tls` + `json`**: se añadió `json`
   (además de `rustls-tls`, ya presente) porque simplifica
   significativamente el código (`RequestBuilder::json`,
   `Response::json::<T>()`) sin añadir ninguna dependencia TLS nueva
   (sigue sin usar `native-tls`, consistente con `lapin`).
5. **Mapeo de errores a status HTTP** (`impl IntoResponse for UsuariosClientError`
   en `src/api.rs`): `Unreachable` (fallo de red/timeout) → `504 Gateway
   Timeout`; `UnexpectedResponse`/`MalformedResponse` (incluye 5xx y 401 de
   credencial de servicio rechazada) → `502 Bad Gateway`; `RequestBuild`
   (fallo interno al construir la solicitud, no imputable a `ms-usuarios`)
   → `500 Internal Server Error`. Ninguno de los mensajes (`#[error(...)]`)
   incluye la URL base de `ms-usuarios`.

Estas 5 decisiones deben confirmarse contra el contrato real de
`user-service` en cuanto esté disponible en este checkout — no son un
bloqueo para cerrar esta feature (así lo indica la tarea), pero si el
contrato real usa otro nombre de header o un shape de perfil tipado, este
módulo es el único punto de cambio (por diseño, capa `usuarios_client`).

## Verificación de cada criterio de aceptación

1. **`get_profile(identity)`/`upsert_profile(identity, ...)` en
   `src/usuarios_client`, reenviando header de identidad + shared secret**:
   implementado en `UsuariosClient::get_profile`/`upsert_profile`
   (`src/usuarios_client.rs:118-165`). Verificado por
   `tests/usuarios_client.rs::get_profile_happy_path_returns_the_profile_from_ms_usuarios`
   y `::upsert_profile_happy_path_returns_the_updated_profile`, que aserta
   contra un stub real que responde `401` si el header de secreto no
   coincide y `400` si falta el header de identidad — ambos tests pasan
   solo porque el cliente los envía correctamente.
2. **Ningún otro módulo hace HTTP directo hacia `ms-usuarios`**: verificado
   con `grep -rn reqwest src/` — el único uso de `reqwest` fuera de
   `usuarios_client.rs` es `openidconnect::reqwest` dentro de `src/auth.rs`,
   que es el cliente HTTP interno de la crate `openidconnect` hacia Google
   (handshake OIDC), no hacia `ms-usuarios`.
3. **Fallo de red/5xx → error tipado → 502/504, sin URL interna en el
   cuerpo**: `UsuariosClientError` (thiserror) con variantes específicas;
   `impl IntoResponse` mapea `Unreachable→504`,
   `UnexpectedResponse/MalformedResponse→502`. Test unitario
   `usuarios_client::tests::error_messages_never_include_the_base_url`
   verifica que ningún mensaje de error contiene el host. Test de
   integración end-to-end
   `tests/usuarios_profile_proxy.rs::profile_when_ms_usuarios_is_unreachable_returns_a_gateway_error_without_leaking_its_url`
   verifica contra el servidor HTTP real del Gateway que la respuesta es
   `502` o `504` y que el cuerpo no contiene la URL base del stub. Ningún
   `unwrap`/`expect`/`panic!` fuera de `#[cfg(test)]` en `usuarios_client.rs`
   ni en el nuevo código de `api.rs`.
4. **`GET /api/profile` (protegida) usa el cliente y devuelve el perfil de
   la sesión activa**: handler `profile` en `src/api.rs:132-138`, montado en
   `protected_router` tras el middleware `require_session`, listado en
   `ROUTES` como `protected: true`. Verificado por
   `tests/usuarios_profile_proxy.rs::profile_with_valid_session_and_healthy_ms_usuarios_returns_the_profile`
   (cuerpo de la respuesta igual al perfil devuelto por el stub) y
   `::profile_without_session_cookie_is_rejected_before_touching_ms_usuarios`
   (401 sin sesión, apuntando `ms-usuarios` a una URL inalcanzable para
   detectar si el middleware dejara pasar la solicitud por error).
5. **Tests de integración contra un servidor HTTP de test real — camino
   feliz, credencial de servicio incorrecta (401), `ms-usuarios` caído
   (502/504) sin panic**: cubierto en `tests/usuarios_client.rs` (6 tests:
   camino feliz GET/PUT, credencial incorrecta → `UnexpectedResponse{401}`,
   5xx explícito → `UnexpectedResponse{500}`, no alcanzable → `Unreachable`
   en GET y PUT) y en `tests/usuarios_profile_proxy.rs` (3 tests end-to-end
   sobre el router real, incluido el caso "caído" → 502/504 sin panic).
   Ninguno de estos tests está marcado `#[ignore]` (no requieren Docker,
   igual que `tests/oidc_login.rs`).

## Resultado de la verificación

- `cargo build 2>&1` → compila sin errores.
- `cargo clippy --all-targets -- -D warnings 2>&1` → sin warnings.
- `cargo fmt --check 2>&1` → sin diferencias (tras `cargo fmt`).
- `cargo test 2>&1` → 19 tests unitarios + 8 (`oidc_login`) + 5
  (`session_middleware_and_me`) + 6 (`usuarios_client`) + 3
  (`usuarios_profile_proxy`) = 41 tests, todos verdes. Las features 1-4 no
  se rompieron.
- `cargo doc --no-deps 2>&1` → genera sin errores (todo ítem público
  documentado).
- `./init.sh` → termina con `[OK] Entorno listo.` y exit code 0.

## Dudas / puntos a confirmar por el reviewer o el usuario

- El shape de `UserProfile` como JSON opaco (`serde_json::Value`) es una
  decisión defendible dado que el contrato real de `user-service` no está
  disponible, pero es más débil en tipado que el resto del código de este
  repo (`Session`, `MeResponse`, etc. sí son tipos concretos). Si el
  contrato real de `user-service` aparece en un checkout futuro, vale la
  pena revisar si conviene tipar `UserProfile` con sus campos reales.
- El nombre de los headers (`X-Gateway-Identity`,
  `X-Gateway-Service-Secret`) y el formato JSON del primero son una decisión
  de este repo, no confirmada contra `user-service/docs/security-scope.md`
  (que menciona genéricamente "un header de identidad" y
  `GATEWAY_SHARED_SECRET" sin dar el nombre exacto de header). Ningún
  bloqueo, pero a confirmar.
- No se implementó ninguna ruta que use `upsert_profile` (no la exige el
  `acceptance` de esta feature, que solo pide la ruta `GET /api/profile`);
  el método existe y está testeado en `usuarios_client` para cuando una
  feature futura lo necesite.
