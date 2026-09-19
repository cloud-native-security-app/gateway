# Review — feature 5 (usuarios_profile_proxy)

**Veredicto:** APPROVED

## Verificación ejecutada por el reviewer (no solo el informe del implementer)

- `cargo build` → compila sin errores/warnings.
- `cargo clippy --all-targets -- -D warnings` → sin advertencias.
- `cargo fmt --check` → sin diferencias.
- `cargo test` → 41 tests, todos verdes (19 unitarios lib + 8 `oidc_login` +
  5 `session_middleware_and_me` + 6 `usuarios_client` + 3
  `usuarios_profile_proxy`). Ninguna feature 1-4 se rompió.
- `./init.sh` → termina con `[OK] Entorno listo.`, exit code 0 (fase Docker
  `[OK] ... o no hay ninguno todavía`, correcto: esta capa no usa
  `testcontainers`).
- `grep -rn reqwest src/` → único uso hacia `ms-usuarios` es
  `src/usuarios_client.rs:28`; el resto (`src/auth.rs:176,196,197`) es
  `openidconnect::reqwest`, cliente interno de esa crate hacia Google, no
  hacia `ms-usuarios`. `grep -n "http://|https://|Client::" src/api.rs` no
  encontró ninguna coincidencia: `api.rs` no construye peticiones HTTP
  directas.
- `grep -n "tracing::" src/api.rs` (únicas líneas 321 y 343, la segunda es
  la de `IntoResponse for UsuariosClientError`) → solo loggea
  `error = %self` (mensaje `thiserror`, sin secreto/URL) y `status`. `grep
  -rn shared_secret src/` confirma que el único lugar donde se usa
  `.expose_secret()` es al construir el header saliente
  (`src/usuarios_client.rs:137,160`), nunca en un `tracing::`/`Debug`.
- `grep -n "unwrap()|expect(|panic!|println!|dbg!" src/usuarios_client.rs
  src/api.rs` → los únicos `.expect(...)` (líneas 211-254) están dentro de
  `#[cfg(test)] mod tests` (arranca en la línea 202); nada fuera de tests.

## Criterios de aceptación (`feature_list.json`, id=5)

1. **`get_profile(identity)`/`upsert_profile(identity, ...)` en
   `src/usuarios_client`, reenviando header de identidad + shared secret**
   — PASA. `UsuariosClient::get_profile`/`upsert_profile`
   (`src/usuarios_client.rs:126-165`) adjuntan `IDENTITY_HEADER_NAME` (JSON
   `{"sub","email"}`, sin `name`, verificado por el test
   `identity_header_value_encodes_sub_and_email`) y
   `SERVICE_SECRET_HEADER_NAME` con `shared_secret.expose_secret()`.
   Verificado extremo a extremo contra un stub HTTP real en
   `tests/usuarios_client.rs` (camino feliz GET/PUT).

2. **Ningún otro módulo hace HTTP directo hacia `ms-usuarios`** — PASA.
   Confirmado con grep propio del reviewer (ver arriba), no solo el grep
   citado por el implementer: `src/api.rs` no importa `reqwest` ni
   construye URLs de `ms-usuarios`; solo llama a
   `state.usuarios_client.get_profile(&session)`
   (`src/api.rs:132-138`).

3. **Fallo de red/5xx → error tipado → 502/504, sin URL interna en el
   cuerpo** — PASA. `UsuariosClientError` (`thiserror`,
   `src/usuarios_client.rs:56-77`) sin `String` genérico.
   `impl IntoResponse for UsuariosClientError` (`src/api.rs:327-347`) mapea
   `Unreachable→504`, `UnexpectedResponse`/`MalformedResponse→502`,
   `RequestBuild→500`. Confirmado con el test unitario
   `error_messages_never_include_the_base_url` y, más fuerte todavía, con
   el test end-to-end
   `tests/usuarios_profile_proxy.rs::profile_when_ms_usuarios_is_unreachable_returns_a_gateway_error_without_leaking_its_url`,
   que golpea el router real y confirma `status ∈ {502,504}` y que el
   cuerpo de texto de la respuesta no contiene la URL base del stub caído.
   Sin panic: único `unwrap`/`expect`/`panic!` en `usuarios_client.rs`
   fuera de tests es cero (confirmado con grep, ver arriba).

4. **`GET /api/profile` (protegida) usa el cliente y devuelve el perfil de
   la sesión activa** — PASA. Ruta montada dentro de `protected_router`
   (`src/api.rs:79-94`, detrás de `middleware::from_fn_with_state(...,
   auth::require_session)`), listada en `ROUTES` con `protected: true`
   (`src/api.rs:189-193`), y el test de enumeración de rutas heredado de la
   feature 4 (`enumerates_routes_and_verifies_which_carry_the_session_middleware`)
   sigue pasando con la ruta nueva incluida — cumple RF-10 explícitamente:
   ninguna ruta protegida queda accesible sin pasar por el middleware de
   sesión. Confirmado también por
   `tests/usuarios_profile_proxy.rs::profile_without_session_cookie_is_rejected_before_touching_ms_usuarios`,
   que apunta `ms-usuarios` a una URL inalcanzable para detectar si el
   middleware dejara pasar la solicitud por error (obtiene 401, no un error
   de red).

5. **Tests de integración contra un servidor HTTP de test real — camino
   feliz, credencial de servicio incorrecta (401), `ms-usuarios` caído
   (502/504) sin panic** — PASA. `tests/usuarios_client.rs` (6 tests,
   servidor `axum::serve` real en puerto efímero, no interceptación a
   nivel de módulo) cubre camino feliz GET/PUT, credencial incorrecta →
   `UnexpectedResponse{401}`, 5xx explícito → `UnexpectedResponse{500}`, no
   alcanzable → `Unreachable` en GET y PUT.
   `tests/usuarios_profile_proxy.rs` (3 tests) cubre el mismo contrato pero
   a través del router real (`app_router`) con sesión real firmada. Ningún
   test de esta capa está marcado `#[ignore]` (correcto: no depende de
   Docker, mismo patrón que `oidc_login`).

## Nota sobre las suposiciones de contrato de `ms-usuarios`

El implementer documentó explícitamente (en el docstring de módulo de
`src/usuarios_client.rs:1-26` y en `progress/impl_usuarios_profile_proxy.md`
§"Decisiones de diseño a confirmar") que el contrato real de `user-service`
no está disponible en este checkout, y marcó como **suposición, no como
contrato confirmado**:

- El nombre de los headers `X-Gateway-Identity` (JSON `{"sub","email"}`) y
  `X-Gateway-Service-Secret`.
- El shape del perfil como JSON opaco (`UserProfile = serde_json::Value`),
  en vez de inventar campos concretos no documentados en este repo.
- El path `GET`/`PUT /users/me`.

Esto es razonable y está bien documentado: coherente con
`docs/architecture.md` §"Qué NO hacer" ("no inventar el shape de la API de
`ms-usuarios`") y con el criterio C3 de `CHECKPOINTS.md`. El cliente y su
propio servidor de test (`tests/usuarios_client.rs`,
`tests/usuarios_profile_proxy.rs`) comparten consistentemente ese mismo
contrato asumido — no hay contradicción interna. El implementer dejó
constancia explícita (sección "Dudas / puntos a confirmar") de que estas 5
decisiones deben revalidarse contra `user-service/docs` en cuanto ese
contrato esté disponible en este checkout. Queda registrado aquí para que
una sesión futura lo verifique antes de dar por definitivo el nombre de
headers/shape — no es un bloqueo para esta feature, tal como indica la
propia tarea del implementer.

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — 4 archivos base + 4 docs existen; `./init.sh` exit 0.
- C2: [x] — una sola feature `in_progress` (id=5) en `feature_list.json`;
  toda feature `done` (1-4) sigue con sus tests pasando;
  `progress/current.md` describe la sesión activa, sin basura de sesiones
  anteriores.
- C3: [x] — `src/` solo contiene los módulos previstos
  (`config`, `domain`, `auth`, `usuarios_client`, `broker`, `realtime`,
  `api`; `main.rs`/`lib.rs`). `reqwest` como dependencia normal está
  justificado por esta feature. Sin `println!`/`dbg!`/`unwrap`/`panic!`
  fuera de tests en el código nuevo (grep del reviewer, ver arriba).
  `cargo doc --no-deps` genera sin errores (confirmado también por
  `./init.sh`). Ninguna feature inventó el shape de una API pendiente — el
  contrato de `ms-usuarios` que sí existe conceptualmente (perfil) se trató
  como JSON opaco en vez de inventar campos, con la suposición marcada
  explícitamente (ver nota arriba); esto es distinto de la "Dependencia
  pendiente" de `network_user`/`ssh_credentials_ref`/`has_sudo` de la
  feature 6, que no aplica aquí.
- C4: [x] — `tests/usuarios_client.rs` y `tests/usuarios_profile_proxy.rs`
  cruzan IO real vía servidor HTTP de test; `cargo test` muestra 41 tests,
  todos verdes; `cargo clippy --all-targets -- -D warnings` sin
  advertencias.
- C5: [x] — no hay archivos sin trackear sospechosos (`git status` solo
  muestra los archivos de esta feature: `Cargo.toml`, `feature_list.json`,
  `progress/current.md`, `src/api.rs`, `src/usuarios_client.rs`,
  `tests/oidc_login.rs`, `tests/session_middleware_and_me.rs`, y los 3
  nuevos de `progress/`/`tests/`); `progress/current.md` refleja la sesión
  activa de la feature 5.

## Cambios requeridos

Ninguno.
