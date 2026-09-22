# Investigación: sesión propia JWT + cookie HttpOnly/Secure/SameSite=Strict

Alcance: solo investigación (sin código de producción). Preguntas originales:
API exacta de `jsonwebtoken` (encode/decode/ErrorKind), forma idiomática de
emitir/leer/borrar la cookie en `axum` 0.7 (¿`axum-extra` o `Set-Cookie`
manual?), y compatibilidad de versiones en `Cargo.toml`.

Fuentes: docs.rs (versión exacta indicada en cada bloque), crates.io API
(fechas de release), fuente en GitHub de `axum-extra` (tag
`axum-extra-v0.9.6`). **Nota de fiabilidad**: la herramienta de fetch usada
resume el HTML con un modelo intermedio, no pega el HTML crudo — los nombres
de tipos/métodos y firmas fueron contrastados contra 2-3 páginas distintas
cuando fue posible, pero el implementer debe confirmar contra
`cargo doc --open` / `Cargo.lock` real antes de dar por buena cualquier firma
exacta (mutabilidad de parámetros, genéricos exactos, etc.).

## 0. Estado actual del repo (`Cargo.toml`, ya leído)

```toml
axum = "0.7"
jsonwebtoken   # NO está en Cargo.toml todavía — hay que agregarlo
axum-extra     # NO está en Cargo.toml todavía — hay que agregarlo (si se recomienda)
secrecy = "0.10.3"
```

`axum` está fijado en la línea **0.7**. Esto es la restricción dura para
cualquier recomendación de `axum-extra` (ver §4).

## 1. API de `jsonwebtoken`

**Versión más reciente en crates.io: `11.1.0`** (release 2026-09-16, i.e.
prácticamente esta semana). Verificado contra la API de crates.io
(`GET /api/v1/crates/jsonwebtoken`), que listó: 11.1.0 > 11.0.0 (2026-07-24)
> 10.4.0 (2026-05-11) > 10.3.0 > 10.2.0. Dado lo reciente de 11.1.0,
considerar pinnear `jsonwebtoken = "11"` (o incluso `"10"` si se prefiere
una serie con más rodaje) en vez de dejarlo sin acotar — es una decisión de
`docs/conventions.md`/leader, no mía.

### `encode`

```rust
pub fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &EncodingKey,
) -> Result<String>   // Result = jsonwebtoken::errors::Result<T>
```

- `Header::default()` usa `alg = HS256` (el default del tipo) — para ser
  explícitos: `Header::new(Algorithm::HS256)`.
- `EncodingKey::from_secret(secret: &[u8]) -> EncodingKey` — construcción
  para HMAC (HS256/384/512). Con `secrecy::SecretString` en `Config`, se
  expone así: `EncodingKey::from_secret(secret.expose_secret().as_bytes())`
  (requiere `secrecy::ExposeSecret` en scope). El `EncodingKey` resultante
  se puede guardar una vez en el estado de la app (no exponer el secreto en
  logs — ya es un lineamiento de `docs/security-scope.md`).

Ejemplo de claims propios (`sub`, `email`, `name`, `exp`, `aud`, `iss`):

```rust
#[derive(Serialize, Deserialize)]
struct SessionClaims {
    sub: String,     // Google sub / id de usuario
    email: String,
    name: String,
    exp: usize,       // segundos desde epoch — jsonwebtoken espera numeric date
    aud: String,
    iss: String,
}

let token = jsonwebtoken::encode(
    &Header::new(Algorithm::HS256),
    &claims,
    &encoding_key,
)?;
```

### `decode` y `Validation`

```rust
pub fn decode<T: DeserializeOwned>(
    token: impl AsRef<[u8]>,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>>
```

- `DecodingKey::from_secret(secret: &[u8]) -> DecodingKey` (misma nota sobre
  `SecretString`/`expose_secret()`).
- `Validation` — campos públicos relevantes (confirmados contra doc de
  `Validation` 11.1.0):
  - `algorithms: Vec<Algorithm>` (default `vec![Algorithm::HS256]`)
  - `aud: Option<HashSet<String>>`, `iss: Option<HashSet<String>>`,
    `sub: Option<String>`
  - `validate_exp: bool` (default `true`), `validate_nbf: bool` (default
    `false`), `validate_aud: bool` (default `true`)
  - `leeway: u64` segundos de tolerancia de reloj para `exp`/`nbf` (default
    `60`)
  - `required_spec_claims: HashSet<String>` (default `{"exp"}`) — si se
    quiere exigir también `aud`/`iss` presentes, agregarlos aquí
    explícitamente con `set_required_spec_claims(&["exp", "aud", "iss"])`.
- Constructores/métodos: `Validation::new(alg: Algorithm) -> Validation`,
  `.set_audience::<T: ToString>(&mut self, items: &[T])`,
  `.set_issuer::<T: ToString>(&mut self, items: &[T])`.

```rust
let mut validation = Validation::new(Algorithm::HS256);
validation.set_audience(&[expected_aud]);
validation.set_issuer(&[expected_iss]);
validation.set_required_spec_claims(&["exp", "aud", "iss"]);

let data: TokenData<SessionClaims> =
    jsonwebtoken::decode(&cookie_value, &decoding_key, &validation)?;
```

### Errores tipados — `jsonwebtoken::errors::ErrorKind`

`Error::kind(&self) -> &ErrorKind` (por referencia) e
`Error::into_kind(self) -> ErrorKind` (consumiendo). `Error` implementa
`std::error::Error` + `Display` + `Clone/Debug/Eq/PartialEq` → compone bien
con `thiserror` (ya es dependencia del repo) para envolverlo en el error
tipado propio del módulo `auth`.

`ErrorKind` es un enum accesible tanto por `jsonwebtoken::errors::ErrorKind`
como (probablemente, re-exportado) por `jsonwebtoken::ErrorKind` — confirmar
el path exacto al implementar, pero `jsonwebtoken::errors::ErrorKind` es el
canónico documentado. Variantes relevantes para este repo (lista completa
de 11.1.0):

| Variante | Cuándo |
|---|---|
| `ExpiredSignature` | `exp` venció → mapear a `401` "sesión expirada" |
| `InvalidSignature` | la firma HMAC no matchea → `401` "sesión inválida" (posible manipulación) |
| `InvalidAudience` | `aud` no está en el set esperado |
| `InvalidIssuer` | `iss` no está en el set esperado |
| `InvalidToken` | shape JWT inválido (no son 3 partes base64) |
| `MissingRequiredClaim(String)` | falta un claim marcado como requerido |
| `InvalidClaimFormat(String)` | claim con tipo/formato incorrecto |
| `ImmatureSignature` | `nbf` en el futuro (no aplica si no se usa `nbf`) |
| `InvalidAlgorithm` | el `alg` del header no está en `validation.algorithms` |
| `MissingAlgorithm` | `Validation.algorithms` vacío (error de config, no de request) |
| (otras) | `InvalidEcdsaKey`, `InvalidEddsaKey`, `InvalidRsaKey`, `RsaFailedSigning`, `Signing`, `InvalidAlgorithmName`, `UnsupportedAlgorithm`, `InvalidKeyFormat`, `InvalidSubject`, `Base64`, `Json`, `Utf8`, `Provider` — no aplican al camino HS256 de este repo |

Para RF-10/RNF-02 (distinguir expirado vs firma inválida vs aud/iss
incorrecta) alcanza con un `match` sobre `error.into_kind()`:

```rust
match jsonwebtoken::decode::<SessionClaims>(token, &key, &validation) {
    Ok(data) => Ok(data.claims),
    Err(e) => match e.into_kind() {
        ErrorKind::ExpiredSignature => Err(SessionError::Expired),
        ErrorKind::InvalidSignature => Err(SessionError::InvalidSignature),
        ErrorKind::InvalidAudience | ErrorKind::InvalidIssuer => Err(SessionError::WrongAudienceOrIssuer),
        other => Err(SessionError::Malformed(other)), // catch-all: enum puede crecer (marcar el match con wildcard, no exhaustivo)
    },
}
```

Nota: como `ErrorKind` puede ganar variantes en el futuro, conviene un
brazo `_ =>` catch-all en vez de listar las ~20 variantes — el propio doc no
indica `#[non_exhaustive]` explícito pero es buena práctica igual.

## 2. Cookies en axum — recomendación

**Confirmo el razonamiento del prompt**: dado que el JWT ya viaja firmado
(HS256, integridad+autenticidad cubiertas por `jsonwebtoken`), **no hace
falta** `cookie-signed` ni `cookie-private` de `axum-extra` — serían una
segunda capa de firma/cifrado redundante sobre un token que ya es
autocontenido y verificable. Recomendación concreta:

> Usar `axum_extra::extract::cookie::CookieJar` **plano** (solo feature
> `cookie`, sin `cookie-signed`/`cookie-private`) como transporte de un JWT
> ya firmado por `jsonwebtoken`. El `CookieJar` de axum-extra da manejo
> idiomático de `Set-Cookie`/parseo de `Cookie` request y se integra con el
> sistema de extractors/responses de axum (`IntoResponseParts`) — evita
> construir el header `Set-Cookie` a mano (parsing de atributos, escaping,
> etc.), sin añadir la complejidad de una `Key` maestra de firma/cifrado
> que `cookie-signed`/`cookie-private` exigirían (y que no tiene dónde vivir
> limpiamente aparte del secreto de `jsonwebtoken`, duplicando superficie de
> secretos en `Config`).

### Ejemplo (login — emitir cookie)

```rust
use axum_extra::extract::cookie::{Cookie, CookieJar};
use cookie::SameSite; // re-exportado también como axum_extra::extract::cookie::SameSite

async fn login_callback(jar: CookieJar /* + resto de extractors OIDC */)
    -> Result<(CookieJar, Redirect), AuthError>
{
    let token = issue_session_jwt(&claims, &encoding_key)?; // jsonwebtoken::encode

    let cookie = Cookie::build(("gateway_session", token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(cookie::time::Duration::minutes(SESSION_TTL_MIN)) // alinear con `exp` del JWT
        .build();

    Ok((jar.add(cookie), Redirect::to("/")))
}
```

### Ejemplo (middleware/handler protegido — leer cookie)

```rust
async fn me(jar: CookieJar) -> Result<Json<UserView>, AuthError> {
    let token = jar.get("gateway_session")
        .ok_or(AuthError::MissingSession)?
        .value();
    let claims = validate_session_jwt(token, &decoding_key, &validation)?;
    // ...
}
```

`CookieJar` implementa lo necesario para combinarse en una tupla de
respuesta axum (`(CookieJar, Redirect)`, `(CookieJar, Json<T>)`, etc.) —
confirmado por el propio ejemplo de doc-comment del crate (patrón
`Result<(CookieJar, Redirect), StatusCode>`).

## 3. Logout — borrar la cookie

Dos formas equivalentes, ambas terminan en `Max-Age=0` + fecha de
expiración en el pasado:

**A. `jar.remove(...)`** (idiomático con axum-extra):

```rust
async fn logout(jar: CookieJar) -> (CookieJar, StatusCode) {
    (jar.remove(Cookie::from("gateway_session")), StatusCode::NO_CONTENT)
}
```

**B. `Cookie::make_removal()`** (de la crate `cookie` 0.18, si se necesita
construir la cookie de borrado a mano, p. ej. para setear explícitamente
`path`/`domain`):

```rust
let mut c = Cookie::new("gateway_session", "");
c.make_removal(); // limpia valor, Max-Age=0, expira en el pasado
```

**Limitación/gotcha a documentar para el implementer**: para que el
navegador realmente borre la cookie, el `Set-Cookie` de borrado debe llevar
el **mismo `path` (y `domain`, si se usó) que la cookie original** — si la
cookie de sesión se emitió con `.path("/")`, el `remove`/`make_removal()`
debe expirar también con `path=/`; si no coinciden, el navegador la trata
como una cookie distinta y la original sigue viva. Verificar que
`jar.remove(Cookie::from("gateway_session"))` (que no especifica `path`)
efectivamente herede/matchee el `path="/"` usado al emitir — si no, usar
`jar.remove(Cookie::build(("gateway_session", "")).path("/"))` explícito.
Esto es justo el tipo de detalle que un test de integración
(`rejects_request_when_session_cookie_is_expired`-style, pero para logout)
debería cubrir.

## 4. Feature flags y compatibilidad de versiones — CONFLICTO ENCONTRADO

**`axum-extra` última versión (`0.12.6`, 2026-07-09) exige `axum ^0.8.9`.**
El repo tiene `axum = "0.7"` fijado en `Cargo.toml`. Usar `axum-extra`
`"latest"`/`0.12.x` **rompería la resolución de dependencias** (cargo no
podría satisfacer axum 0.7 del repo + axum ^0.8.9 que pide axum-extra
0.12.x en la misma unidad de compilación, salvo que también se suba axum a
0.8 — fuera del alcance de esta investigación, y no es gratis: 0.8 tiene
cambios de breaking API en extractors/routing).

**Versión correcta a fijar: `axum-extra = "0.9.6"`** (release
2026-11-16 2024, la última de la serie 0.9.x) — su `Cargo.toml` fuente
(confirmado en `docs.rs/crate/axum-extra/0.9.6/source/Cargo.toml`) declara
`axum = { version = "0.7.8", default-features = false, features =
["original-uri"] }`, compatible con el `axum = "0.7"` ya fijado en este
repo. La serie `0.10.x` de axum-extra ya targetea axum 0.8 también
(rc/alpha desde oct-dic 2024) — evitarla mientras el repo siga en axum 0.7.

Features de Cargo.toml a agregar:

```toml
axum-extra = { version = "0.9.6", default-features = false, features = ["cookie"] }
```

- `cookie` → habilita `CookieJar`/`Cookie` (dependencia `cookie = "0.18.0"`,
  con su propia feature `percent-encode` ya activada internamente por
  axum-extra).
- **No** agregar `cookie-signed` ni `cookie-private` (ver razonamiento §2) —
  se apoyan en `cookie::Key`, que sería un segundo secreto a gestionar sin
  necesidad, dado que la integridad ya la da la firma HS256 del JWT.
- `default-features = false` es opcional pero recomendable para no arrastrar
  otras integraciones de axum-extra (`typed-header`, `query`, `form`, etc.)
  que este repo no usa todavía — activar solo lo que se necesita, alineado
  con la filosofía "sin dependencias sin usar" que ya se ve en
  `lapin = { version = "2", features = ["rustls"], default-features = false }`.

## 5. Resumen accionable para el implementer

1. `Cargo.toml`: agregar `jsonwebtoken = "11"` (o `"10"` si se prefiere más
   rodaje) y `axum-extra = { version = "0.9.6", default-features = false, features = ["cookie"] }`
   — **nunca** `axum-extra` `"latest"`/`0.12`/`0.10` mientras `axum` siga en
   `"0.7"`, por el conflicto de versiones arriba.
2. `auth`: `EncodingKey`/`DecodingKey::from_secret(secret.expose_secret().as_bytes())`
   sobre el secreto de `Config` (`SecretString` de `secrecy`, ya dependencia
   del repo).
3. Emitir: `Cookie::build(("gateway_session", jwt)).http_only(true).secure(true).same_site(SameSite::Strict).path("/").max_age(...)`, `jar.add(cookie)`.
4. Validar: `Validation::new(Algorithm::HS256)` + `set_audience`/`set_issuer`
   + `set_required_spec_claims(&["exp","aud","iss"])`; mapear
   `error.into_kind()` a un error tipado propio (`thiserror`) con brazo
   catch-all `_ =>` para robustez ante nuevas variantes.
5. Logout: `jar.remove(...)` con el mismo `path` usado al emitir — cubrir
   con test de integración que el `Set-Cookie` de respuesta tenga
   `Max-Age=0`/fecha pasada y el mismo `path`.

## Ambigüedades / cosas a re-verificar al implementar (no bloqueantes)

- No pude confirmar 100% si `jsonwebtoken::ErrorKind` está re-exportado en
  la raíz del crate o solo en `jsonwebtoken::errors::ErrorKind` — usar el
  path `jsonwebtoken::errors::ErrorKind` (documentado con certeza) para no
  depender de un re-export no confirmado.
- `jsonwebtoken 11.1.0` es una release de esta misma semana (2026-09-16);
  si el equipo prefiere una serie con más historial en producción, `"10"`
  (10.4.0, 2026-05-11) es la alternativa más conservadora — no encontré
  breaking changes documentados entre 10.x y 11.x en esta investigación
  (no profundicé el CHANGELOG completo), así que si se elige 10.x habría
  que revalidar los nombres de métodos igual (deberían ser estables, la API
  pública de encode/decode/Validation no ha cambiado en varias majors).
- No verifiqué con un `cargo add`/build real (fuera de alcance de una
  investigación de solo lectura) — las firmas están tomadas de docs.rs vía
  fetch resumido por IA, no de HTML crudo; el implementer debe correr
  `cargo doc` o revisar `Cargo.lock` post-`cargo add` antes de codear contra
  ellas a ciegas.
