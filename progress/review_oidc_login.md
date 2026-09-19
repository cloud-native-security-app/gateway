# Review — feature 3 (oidc_login)

**Veredicto:** APPROVED

## Verificación de entorno (ejecutada por el reviewer, no solo confiando en el informe)

- `cargo build` → compila sin warnings.
- `cargo fmt --check` → sin diferencias.
- `cargo clippy --all-targets -- -D warnings` → sin warnings.
- `cargo test` (sin `--ignored`) → 12 unit + 8 integración (`tests/oidc_login.rs`) + 0 doctests, todos `ok`. Confirmado que los 8 tests de `tests/oidc_login.rs` corren y pasan en `cargo test` normal.
- `cargo test -- --ignored` → 0 tests ejecutados (no hay ningún `#[ignore]` en esta feature; coherente con la excepción documentada).
- `./init.sh` → termina en `[0;32m[OK][0m Entorno listo. Puedes empezar a trabajar.` (incluye `cargo doc --no-deps` sin warnings).

## Criterios de aceptación (feature_list.json id=3)

1. **`GET /auth/login` → 302 con client_id/redirect_uri/scope `openid email profile`/state**: PASA.
   Evidencia: `src/api.rs:52-61` construye la respuesta vía `redirect_found` (`StatusCode::FOUND` = 302, no 303). Test `login_redirects_to_authorization_endpoint_with_oidc_params` (`tests/oidc_login.rs:290-334`) verifica status 302 y cada parámetro de query (`client_id`, `redirect_uri`, `response_type=code`, `scope` contiene `openid`/`email`/`profile`, `state` presente).

2. **`/auth/callback` valida firma JWKS + aud + iss + exp, rechaza 401/400 sin crear sesión**: PASA.
   Evidencia: `src/auth.rs:258-259` usa `self.core.id_token_verifier()` + `id_token.claims(&verifier, nonce)` (validación real de `openidconnect`, no reimplementada). `From<ClaimsVerificationError>` (`src/auth.rs:110-127`) mapea a variantes específicas. Los 3 casos exigidos están probados con tokens firmados por el IdP de prueba:
   - `callback_rejects_id_token_with_wrong_audience` (`tests/oidc_login.rs:424-462`): `aud: "some-other-client-id"` → 401, sin `Set-Cookie`.
   - `callback_rejects_expired_id_token` (`tests/oidc_login.rs:464-502`): `exp` en el pasado → 401, sin `Set-Cookie`.
   - `callback_rejects_id_token_with_invalid_signature` (`tests/oidc_login.rs:504-547`): firma con una clave RSA distinta a la publicada en el JWKS (mismo `kid`, a propósito, para forzar el rechazo criptográfico y no solo un "kid no encontrado") → 401, sin `Set-Cookie`.

3. **Sesión propia (sub/email/name + exp acorde a `SESSION_TTL_SECS`) como cookie HttpOnly+Secure+SameSite=Strict**: PASA.
   Evidencia: `src/auth.rs:406-415` (`session_cookie`) fija los 3 atributos + `path=/` + `max_age`. Test de integración `callback_with_valid_id_token_creates_session` (`tests/oidc_login.rs:336-422`) lee el header `Set-Cookie` real de la respuesta HTTP y comprueba las 3 subcadenas (`httponly`, `secure`, `samesite=strict`), decodifica el JWT con la clave/aud/iss de la config de prueba y compara `sub`/`email`/`name`/`exp`. `exp` se calcula en `src/api.rs:99` como `now + session_ttl_secs` (viene de `AppState::session_ttl_secs`, poblado desde `Config::session_ttl_secs` en producción). Test unitario adicional `session_cookie_has_hardened_attributes` (`src/auth.rs:465-474`) verifica los atributos de la cookie de forma aislada.

4. **`state` generado en login validado en callback; ausente/no coincidente se rechaza**: PASA.
   Evidencia: `src/api.rs:87-91` (`MissingState`/`InvalidState`), `LoginStateStore::take` (`src/auth.rs:341-351`) es de un solo uso (elimina la entrada exista o no). Tests `callback_rejects_missing_state` (400) y `callback_rejects_state_that_does_not_match_any_pending_login` (400) en `tests/oidc_login.rs`.

5. **ID token de Google nunca loggeado/persistido/reenviado**: PASA.
   Evidencia: `grep -rn "tracing::" src/` solo devuelve `src/api.rs:162` (`tracing::warn!(error = %self, %status, ...)`, que loggea el `Display` de `AuthError` — mensajes genéricos definidos en el enum, nunca el JWT crudo) y `src/lib.rs:23` (`"starting"`, sin relación). `GoogleIdentity` (`src/auth.rs:136-144`) solo contiene `sub`/`email`/`name`, nunca el token crudo. `exchange_and_verify` (`src/auth.rs:241-280`) no retiene el `id_token`/`token_response` más allá de esta función. Test `callback_with_valid_id_token_creates_session` afirma explícitamente que el cuerpo de la respuesta no contiene el ID token crudo (`tests/oidc_login.rs:411-419`).

6. **`POST /auth/logout` borra la cookie**: PASA.
   Evidencia: `src/api.rs:118-121` usa `jar.remove(auth::removal_cookie())`; `removal_cookie()` (`src/auth.rs:421-423`) usa mismo nombre/`path` que `session_cookie`. Test `logout_clears_the_session_cookie` (`tests/oidc_login.rs:602-640`) envía un request con la cookie ya puesta y confirma `204` + `Set-Cookie` con `max-age=0` o `expires=` en el pasado, mismo nombre de cookie.

7. **Tests de integración de los 4 escenarios, corriendo sin `--ignored`**: PASA.
   Evidencia: `tests/oidc_login.rs` contiene 8 `#[tokio::test]` sin ningún `#[ignore]`, todos verdes en `cargo test` (ver arriba). Cubren: login redirige con parámetros correctos; callback válido crea sesión; callback rechaza aud incorrecta/expirado/firma inválida (3 tests); state ausente y state no coincidente (2 tests); logout borra cookie. Esto cumple la decisión ya confirmada por el usuario (documentada en `progress/current.md`), que reemplaza para esta feature la redacción literal de `docs/verification.md` Nivel 3.

## Otras verificaciones

- **`docs/architecture.md` (capas)**: el cambio se mantiene dentro de `auth`/`api`/`domain`. `auth.rs` no implementa el middleware de validación de sesión en rutas protegidas (explícitamente diferido a la feature 4, según el propio doc-comment del módulo y la nota del implementer) — confirmado que no existe ninguna función `validate_session`/`decode` reutilizable fuera de tests. `api.rs` no expone `/api/me`, perfil, escaneos ni SSE. `broker.rs`/`realtime.rs`/`usuarios_client.rs` siguen siendo solo el doc-comment del módulo (sin tocar). No se introdujo ninguna capa nueva.
- **`src/config.rs` diff**: mínimo y coherente con el patrón ya existente (`required_string`/`required_secret` → nuevo `optional_string_with_default`, misma forma de constante `ENV_*`/`DEFAULT_*`, mismo estilo de test). No reescribe nada de la feature 2 ya `done`; solo añade `GOOGLE_OIDC_ISSUER_URL` (opcional, default a Google real) — justificado por el hallazgo de `progress/explore_openidconnect.md` (necesario para apuntar a un IdP de prueba en tests sin mockear módulos).
- **`docs/conventions.md`**: `thiserror` con variantes específicas en `AuthError`; sin `unwrap()`/`expect()`/`panic!()` en código de producción nuevo (`src/auth.rs`, `src/api.rs`) — el único patrón repetido es `.lock().unwrap_or_else(|poison| poison.into_inner())` para recuperación de mutex envenenado, que no es un `unwrap()` que pueda entrar en pánico. Todo ítem público tiene rustdoc (`cargo doc --no-deps` sin warnings, confirmado por `init.sh`). Imports ordenados `std` → externos → `crate::` en ambos archivos. Nombres de test descriptivos (`rejects_*`, `creates_*`).
- **`docs/security-scope.md`**: sin hallazgos — ver criterio 5 arriba. `Cargo.toml` no introduce ninguna credencial hardcodeada; `session_signing_key`/`google_client_secret` siguen viajando como `SecretString` desde `Config`.
- **`CHECKPOINTS.md`**:
  - C1: [x] — 4 archivos base + 4 docs existen, `./init.sh` exit 0.
  - C2: [x] — una sola feature `in_progress` (id=3, y solo se cambió `pending`→`in_progress`, no `done`); `progress/current.md` describe la sesión activa sin basura.
  - C3: [x] — `src/` solo tiene los módulos previstos; toda dependencia nueva de `Cargo.toml` (`openidconnect`, `jsonwebtoken`, `axum-extra`, `cookie` en producción; `rsa`/`rand`/`base64`/`reqwest`/`url` en dev) está justificada por esta feature; sin `println!`/`dbg!`/`unwrap()`/`panic!()` sueltos sin justificar; `cargo doc --no-deps` sin warnings; no se inventó el shape de ninguna API pendiente.
  - C4: [x] — hay tests de integración de `auth` (`tests/oidc_login.rs`); `cargo test` > 0 tests, todos verdes; `cargo clippy --all-targets -- -D warnings` sin advertencias. (El ítem sobre `broker` contra RabbitMQ real no aplica todavía: esa feature no se ha implementado.)
  - C5: [x] — no hay archivos sospechosos sin trackear (`progress/explore_*.md`, `progress/impl_oidc_login.md`, `tests/` son esperados de esta sesión); `progress/history.md` y el estado final de la feature son responsabilidad del leader tras este veredicto, no bloquean la aprobación del código en sí.

## Cambios requeridos

Ninguno. Feature 3 (`oidc_login`) aprobada. El leader puede marcarla `done` en `feature_list.json` una vez cierre la sesión según su propio protocolo.
