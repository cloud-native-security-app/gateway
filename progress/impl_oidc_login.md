# Implementación: feature 3 — oidc_login

> Autor: implementer (sesión 2026-09-19). Referencias leídas antes de
> codear: `feature_list.json` (id=3), `docs/architecture.md`,
> `docs/security-scope.md`, `docs/conventions.md`, `docs/verification.md`,
> `CHECKPOINTS.md`, y los 3 informes de `progress/explore_*.md`.

## Archivos creados/modificados

- `Cargo.toml`: agrega `openidconnect = "4.0.1"`,
  `jsonwebtoken = { version = "11.1.0", features = ["rust_crypto"] }`,
  `axum-extra = { version = "0.9.6", default-features = false, features =
  ["cookie"] }`, `cookie = { version = "0.18.2", default-features = false }`
  (dependencia directa porque `auth.rs` usa `cookie::time::Duration` y
  `Cookie`/`SameSite`, transitivos vía `axum-extra` pero Cargo exige
  declararlos directos para poder nombrarlos). `dev-dependencies`: `rsa`,
  `rand`, `base64` (generar el keypair/JWKS del IdP de prueba y codificar
  `n`/`e`), `reqwest` (cliente HTTP de test, con `rustls-tls`, sin
  `default-features` para no arrastrar `native-tls`), `url` (parsear el
  `Location` del login y extraer `state`/`nonce`).
  - Nota importante encontrada en runtime (no la traían los explorers):
    `jsonwebtoken` 11.1.0 no trae ningún backend criptográfico por
    defecto (`default = ["use_pem"]` únicamente) — sin activar
    `rust_crypto` o `aws_lc_rs`, `encode`/`decode` **entran en pánico** en
    tiempo de ejecución ("Could not automatically determine the
    process-level CryptoProvider"). Elegí `rust_crypto` (crates
    RustCrypto: `hmac`, `sha2`, `rsa`, etc.) por no requerir toolchain de
    compilación C/cmake como `aws_lc_rs`, y porque ya usamos `rsa` en
    dev-dependencies para el IdP de prueba.
- `src/config.rs`: añade `GOOGLE_OIDC_ISSUER_URL` (opcional, con default
  `https://accounts.google.com` vía nuevo helper
  `optional_string_with_default`) y el campo `Config::google_oidc_issuer_url`.
  Nuevos tests: `google_oidc_issuer_url_can_be_overridden_for_tests`, y
  aserción de default en `loads_valid_config_from_env`. No se tocó ninguna
  otra parte de la feature 2 (ya `done`).
- `src/domain.rs`: nuevo tipo `Session { sub, email, name, exp }` (identidad
  verificada + validez temporal, sin datos de Google ni `aud`/`iss` del
  JWT, que son detalle de codificación de `auth`).
- `src/auth.rs` (antes solo el doc-comment del módulo): implementa
  - `AuthError` (`thiserror`, variantes específicas: `Discovery`,
    `TokenExchange`, `MissingIdToken`, `IdTokenExpired`,
    `IdTokenInvalidSignature`, `IdTokenInvalidAudienceOrIssuer`,
    `IdTokenInvalidNonce`, `IdTokenRejected`, `MissingIdentityClaim`,
    `MissingState`, `InvalidState`, `MissingCode`, `SessionIssue`) +
    `From<openidconnect::ClaimsVerificationError>` (con brazo `_` porque
    ese enum es `#[non_exhaustive]`).
  - `OidcClient`: `discover()` (discovery + JWKS vía
    `CoreProviderMetadata::discover_async`, cliente `reqwest` con
    `redirect::Policy::none()` anti-SSRF, tal como advierte la doc de
    `openidconnect`), `begin_login()` (URL de autorización con scopes
    `email`+`profile` — `openid` ya lo añade la crate por defecto —, PKCE,
    `state`/`nonce` generados), `exchange_and_verify()` (intercambio de
    código + `id_token.claims(&verifier, &nonce)` que valida firma/JWKS +
    `aud` + `iss` + `exp` + `nonce`; extrae `sub`/`email`/`name` y
    **descarta el ID token** — nunca se guarda en ningún struct que
    sobreviva la llamada).
  - `LoginStateStore`: store en memoria (`Mutex<HashMap<String,
    LoginStateEntry>>`) del `state`→(`nonce`, `pkce_verifier`), con TTL de
    10 min y `take()` de un solo uso (se elimina al consultarlo, exista o
    no, para que un reintento con el mismo `state` falle). Documenté la
    limitación (no sobrevive reinicio, no se comparte entre instancias)
    como decisión de diseño simple, tal como pedía el prompt.
  - `issue_session_token()` (JWT HS256 con `sub/email/name/exp/aud/iss`),
    `session_cookie()` y `removal_cookie()` (mismo nombre/`path=/` para que
    el navegador pueda borrarla en logout).
  - **Deliberadamente NO implementé** una función de validación de la
    sesión propia (`decode`/`validate_session`): el prompt pide no tocar
    el middleware de sesión (feature 4), y decidí no adelantar ni siquiera
    la función pura de validación para no insinuar ese trabajo; los tests
    decodifican el JWT emitido con `jsonwebtoken::decode` directamente.
  - Tests unitarios (`#[cfg(test)] mod tests`): emisión de JWT con claims
    esperadas, atributos de la cookie (`HttpOnly`/`Secure`/`SameSite=Strict`/
    `path`), cookie de borrado con mismo nombre/`path`, y 3 tests de
    `LoginStateStore` (round-trip, `state` desconocido, uso único).
- `src/api.rs` (antes solo el doc-comment): `AppState` (todos los campos
  `pub` para que el test de integración pueda construirlo directamente sin
  un módulo `wiring` — esta feature no lo necesita todavía),
  `auth_router()` monta `GET /auth/login`, `GET /auth/callback`, `POST
  /auth/logout`. Handlers `login`/`callback`/`logout` tal como describe el
  criterio de aceptación. `redirect_found()` construye el `302 Found` a
  mano (`axum::response::Redirect::to` responde `303 See Other`, y el
  criterio exige `302` explícitamente). `impl IntoResponse for AuthError`
  vive aquí (no en `auth.rs`) porque es la traducción error→HTTP, propia
  de la capa `api`; loggea con `tracing::warn!` el `Display` del error
  (nunca el ID token ni la sesión) antes de responder con el mismo mensaje
  genérico al cliente.
- `tests/oidc_login.rs` (nuevo): 8 tests de integración, todos sin
  `#[ignore]` (decisión ya confirmada por el usuario, documentada en
  `progress/current.md` y en el doc-comment del propio archivo). Levanta
  un IdP OIDC de prueba en memoria (discovery + JWKS + `/token`, con
  `axum::serve` sobre `TcpListener::bind("127.0.0.1:0")`) y el router real
  de `gateway::api` en otro puerto efímero; usa RSA real (`rsa` +
  `jsonwebtoken::jwk`) para firmar IDs tokens de prueba y servir su JWKS.

## Decisiones de diseño destacadas

- **`GOOGLE_OIDC_ISSUER_URL` opcional con default a Google real**: seguí
  el patrón sugerido en el prompt/explorer en vez de hacerla requerida,
  para no romper ninguna instalación existente que ya seteaba el resto de
  variables de la feature 2 sin conocer esta nueva.
- **`cookie` como dependencia directa**: aunque `axum-extra` ya la trae
  transitiva, Rust no permite `use cookie::...` de una dependencia no
  declarada directamente en `Cargo.toml`, así que la añadí fijada a la
  misma versión que ya resolvía el lockfile (0.18.2) — no hay dos copias
  de la crate compilándose.
- **`reqwest`/`url` en `dev-dependencies`**: el código de producción de
  `auth.rs` usa exclusivamente `openidconnect::reqwest::Client` (el
  re-export interno de `openidconnect`/`oauth2`) para no añadir una
  segunda instancia de `reqwest` fijada a mano en producción; en los tests
  sí declaro `reqwest`/`url` directos por legibilidad, ya que de todos
  modos ya estaban resueltos transitivamente a esas versiones exactas.
- **PKCE**: añadido aunque no lo exige explícitamente el criterio de
  aceptación, porque `openidconnect` lo soporta con muy poco costo y es
  buena práctica recomendada por la propia crate para clientes que hacen
  el intercambio de código (RF-01, mismo espíritu que `docs/architecture.md`
  al no reinventar seguridad).
- **`nonce` en el ID token**: es obligatorio para que
  `id_token.claims(&verifier, &nonce)` no rechace el token con
  `InvalidNonce` — lo cual descubrí en la primera corrida de tests
  (`missing nonce claim`). El IdP de prueba y el test firman el ID token
  con el mismo `nonce` que devolvió `/auth/login` en la URL de
  autorización.
- **Status codes**: 400 para `MissingState`/`InvalidState`/`MissingCode`/
  `TokenExchange`/`MissingIdToken`/`MissingIdentityClaim` (fallos de la
  solicitud/protocolo), 401 para cualquier fallo de validación del ID
  token (`IdTokenExpired`/`IdTokenInvalidSignature`/
  `IdTokenInvalidAudienceOrIssuer`/`IdTokenInvalidNonce`/`IdTokenRejected`),
  500 para `Discovery`/`SessionIssue` (fallos internos de este Gateway).
  Los mensajes de error son genéricos en español, sin URLs/credenciales
  (verificado, ver más abajo).

## Verificación de cada criterio de aceptación

1. **`GET /auth/login` → 302 con `client_id`/`redirect_uri`/`scope openid
   email profile`/`state`**: test
   `login_redirects_to_authorization_endpoint_with_oidc_params` (verifica
   status `302`, origen de la URL, y cada parámetro de query uno por uno,
   incluyendo que `scope` contenga las 3 palabras).
2. **`GET /auth/callback` intercambia código, valida ID token (firma
   JWKS/`aud`/`iss`/`exp`) con `openidconnect`, rechaza 401/400 sin crear
   sesión**: tests `callback_rejects_id_token_with_wrong_audience` (401,
   sin `Set-Cookie`), `callback_rejects_expired_id_token` (401, sin
   `Set-Cookie`), `callback_rejects_id_token_with_invalid_signature` (401,
   firmado con una clave distinta a la publicada en el JWKS pero mismo
   `kid`, sin `Set-Cookie`).
3. **Sesión propia firmada con `sub`/`email`/`name` y `exp` acorde a
   `SESSION_TTL_SECS`, cookie `HttpOnly`+`Secure`+`SameSite=Strict`**:
   test `callback_with_valid_id_token_creates_session` decodifica la
   cookie emitida con la clave/`aud`/`iss` de la config de prueba y
   compara `sub`/`email`/`name`/`exp`; test unitario
   `session_cookie_has_hardened_attributes` verifica los atributos de la
   cookie directamente.
4. **`state` validado, rechaza ausente/no coincidente**: tests
   `callback_rejects_missing_state` (400) y
   `callback_rejects_state_that_does_not_match_any_pending_login` (400).
5. **ID token descartado, nunca persistido/loggeado/reenviado**: revisión
   de código (`GoogleIdentity` no contiene el token crudo; `AuthError`
   tampoco; no hay ningún `tracing::*!`/`println!`/`eprintln!` que
   incluya el ID token o la sesión completa en todo `src/`) + aserción
   explícita en `callback_with_valid_id_token_creates_session` de que el
   cuerpo de la respuesta HTTP no contiene el ID token crudo.
6. **`POST /auth/logout` borra la cookie**: test
   `logout_clears_the_session_cookie` (simula un navegador que ya trae la
   cookie —`CookieJar::remove` de `axum-extra`/`cookie` solo emite
   `Set-Cookie` de borrado para cookies que el request declara tener,
   comportamiento documentado del propio crate `cookie`— y verifica
   `204` + `Set-Cookie` con `Max-Age=0`/`Expires` en el pasado, mismo
   nombre).
7. **8 tests de integración, sin `#[ignore]`**: `tests/oidc_login.rs`
   corre en `cargo test` normal (verificado, ver comandos abajo).

## Resultado de los comandos de verificación

```
cargo build          -> compila sin warnings
cargo fmt --check    -> sin diferencias
cargo clippy --all-targets -- -D warnings -> sin warnings
cargo test           -> 12 unit + 8 integración + 0 doctests, todos OK
cargo test -- --ignored -> 0 tests (no hay ninguno marcado #[ignore] en esta feature)
cargo doc --no-deps  -> genera sin warnings (tras corregir un intra-doc-link
                        a un item privado)
./init.sh            -> [OK] Entorno listo. Puedes empezar a trabajar.
```

## Dudas / posibles observaciones para el reviewer

- `AppState` (en `src/api.rs`) tiene todos sus campos `pub` para que el
  test de integración la construya sin pasar por un `wiring` que esta
  feature no crea (el prompt indicaba que probablemente no existe
  todavía). Cuando se implemente la feature `wiring`/`session_middleware_and_me`,
  convendría revisar si esos campos deben volverse privados con un
  constructor `AppState::new(...)`.
- No implementé validación de la sesión propia (`jsonwebtoken::decode`
  reutilizable) en `auth.rs` a propósito, para no adelantar trabajo de la
  feature 4 (`session_middleware_and_me`) — los tests decodifican
  directamente con `jsonwebtoken` en el archivo de test.
- `LoginStateStore` es un store puramente en memoria de un solo proceso;
  documentado como limitación conocida en el doc-comment del struct, tal
  como autorizaba el prompt ("no la sobre-ingenieres").
