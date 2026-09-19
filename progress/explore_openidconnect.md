# Exploración: API de `openidconnect` para el login OIDC contra Google

> Método: `cargo add openidconnect` en un proyecto temporal fuera del repo
> (no se tocó el `Cargo.toml` real), `cargo fetch`, y lectura directa del
> código fuente descargado en
> `~/.cargo/registry/src/index.crates.io-*/openidconnect-4.0.1` (y su
> dependencia `oauth2-5.0.0`, de donde reexporta varios tipos). Se
> contrastó contra docs.rs y crates.io. El repo **no tenía `openidconnect`
> ni `reqwest` en `Cargo.toml`/`Cargo.lock` todavía** (verificado: `grep
> openidconnect Cargo.lock` no encontró nada) — esta es la primera vez que
> se fija la versión.

## Versión a fijar

```toml
openidconnect = "4.0.1"   # última estable en crates.io (confirmado vía crates.io API: max_version = max_stable_version = newest_version = "4.0.1")
```

Features por defecto de `openidconnect` 4.0.1: `reqwest` + `rustls-tls`
(confirmado en `openidconnect-4.0.1/Cargo.toml`: `default = []` no existe
como tal, pero `[features] reqwest = ["oauth2/reqwest"]`,
`rustls-tls = ["oauth2/rustls-tls"]`, y **ambas están en `default`** de
`oauth2` 5.0.0, que es de quien realmente cuelga el default: `oauth2`
declara `default = ["reqwest", "rustls-tls"]`, y `oauth2` depende de
`reqwest = { version = "0.12", optional = true, default-features = false }`
— es decir, **reqwest se trae sin TLS por defecto de reqwest, y
`rustls-tls` habilita `reqwest/rustls-tls` explícitamente. `native-tls`
nunca se activa a menos que se pida la feature `native-tls` a mano.**

**Conclusión para este repo:** no hace falta tocar features. Con
`openidconnect = "4.0.1"` a secas (sin `default-features = false`, sin
listar features) ya se obtiene reqwest+rustls, consistente con `lapin =
{ version = "2", features = ["rustls"], default-features = false }` que ya
usa el repo. Feature flags disponibles pero **no necesarias** aquí:
`reqwest-blocking`, `curl`, `ureq`, `native-tls`,
`timing-resistant-secret-traits`, `accept-rfc3339-timestamps`,
`accept-string-booleans`.

## 1. Construir el cliente y hacer configurable el issuer/discovery URL

**Sí, `openidconnect` soporta discovery contra una URL arbitraria** — no
está hardcodeado a Google. La función clave:

```rust
use openidconnect::core::CoreProviderMetadata;
use openidconnect::IssuerUrl;

let provider_metadata = CoreProviderMetadata::discover_async(
    IssuerUrl::new(config.oidc_issuer_url.clone())?, // <- viene de Config, no literal
    &http_client,
)
.await?;
```

`discover_async` (en `src/discovery/mod.rs:308`) hace `issuer_url.join(".well-known/openid-configuration")`,
pide ese documento, **y además, dentro de la misma llamada, hace un
segundo fetch a `jwks_uri` con `JsonWebKeySet::fetch_async(...)`** y
guarda el JWKS ya resuelto dentro del `ProviderMetadata` devuelto (código
verificado, líneas 308-340). Esto es importante: **el JWKS se descarga una
sola vez, en discovery, no en cada verificación de token.**

`discover_async` también valida que el campo `"issuer"` del documento de
discovery devuelto coincida *exactamente* (string equality) con la
`IssuerUrl` que se le pasó (línea 383-391) — si no coincide, error
`DiscoveryError::Validation`. **Para el IdP de prueba esto importa**: el
documento `/.well-known/openid-configuration` que sirva el servidor de
test debe declarar `"issuer"` igual al `IssuerUrl` exacto que use el test
(p. ej. si el test arranca en `http://127.0.0.1:PORT`, el discovery doc
debe decir `"issuer": "http://127.0.0.1:PORT"`, sin barra final si el
`IssuerUrl` tampoco la lleva).

Luego, construir el cliente:

```rust
use openidconnect::core::CoreClient;
use openidconnect::{ClientId, ClientSecret, RedirectUrl};

let client = CoreClient::from_provider_metadata(
    provider_metadata,
    ClientId::new(config.google_client_id.clone()),
    Some(ClientSecret::new(config.google_client_secret.expose_secret().to_string())),
)
.set_redirect_uri(RedirectUrl::new(config.google_redirect_uri.clone())?);
```

`from_provider_metadata` (client.rs:242) copia `jwks`, `issuer`,
`authorization_endpoint`, `token_endpoint` desde el `ProviderMetadata` ya
resuelto — **no hace I/O propio**.

### Recomendación concreta de configurabilidad (gap detectado)

`src/config.rs` **hoy no tiene ninguna variable de entorno para el
issuer/discovery URL** (grep de `issuer|discovery|ISSUER|DISCOVERY` en
`config.rs` no encontró nada — solo existen `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`). Hace falta añadir algo
como:

```rust
const ENV_GOOGLE_ISSUER_URL: &str = "GOOGLE_OIDC_ISSUER_URL";
// default: "https://accounts.google.com" si no está seteada,
// override en tests de integración a "http://127.0.0.1:<puerto-del-IdP-de-prueba>"
```

Sin esto, el cliente OIDC de producción no se puede apuntar a un IdP de
prueba local y el Nivel 3 de `docs/verification.md` (servidor HTTP de test
con JWKS propio) sería imposible de cumplir sin mockear el módulo, lo cual
`docs/verification.md` prohíbe explícitamente.

**Alternativa sin discovery** (por si el IdP de prueba no quiere implementar
`/.well-known/openid-configuration`): `openidconnect` permite construir el
cliente a mano con `Client::new(client_id, issuer, jwks)` (client.rs:189)
y luego `.set_auth_uri(...)`/`.set_token_uri(...)` explícitos — pero
**no es necesario** para este caso: es más simple y más fiel a producción
que el IdP de prueba sirva un discovery doc real + JWKS real, que es
justo lo que pide `docs/verification.md` ("servidor HTTP de test que sirve
un JWKS" — se puede extender a servir también el discovery doc).

## 2. URL de autorización, `state` (CSRF) y `nonce`

```rust
use openidconnect::{CsrfToken, Nonce, Scope};
use openidconnect::core::CoreAuthenticationFlow;

let (auth_url, csrf_token, nonce) = client
    .authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    )
    .add_scope(Scope::new("email".to_string()))
    .add_scope(Scope::new("profile".to_string()))
    .url();
```

**No hace falta añadir el scope `openid`**: `Client` tiene
`use_openid_scope: true` por defecto (client.rs, `enable_openid_scope` /
`disable_openid_scope`) y `authorize_url` lo agrega automáticamente. Solo
hay que añadir `email` y `profile` a mano.

`csrf_token` y `nonce` deben guardarse (asociados a la sesión de login en
curso, p. ej. en una cookie corta firmada o en un store server-side
keyed por un id de sesión de login) para compararlos en el callback.

**Validación del `state` al volver: NO la hace la crate por ti.** El
propio doc-comment de `openidconnect` lo dice literalmente: *"For security
reasons, your code should verify that the `state` parameter returned by
the server matches `csrf_state`"*. El tipo `CsrfToken` (reexportado de
`oauth2`, definido con la macro `new_secret_type!` en
`oauth2-5.0.0/src/types.rs:554`) expone `.secret() -> &String`. Comparación
manual:

```rust
if returned_state != csrf_token.secret().as_str() {
    return Err(/* CSRF inválido */);
}
```

`Nonce` funciona igual (mismo macro, mismo `.secret()`), pero el `nonce`
**sí lo valida la propia crate** dentro de `id_token.claims(&verifier,
&nonce)` (ver punto 4) — no hace falta compararlo a mano, solo hay que
pasarlo.

Nota: sin la feature `timing-resistant-secret-traits`, `CsrfToken`/`Nonce`
no implementan `PartialEq` directamente (a propósito, para forzar pensar
en comparación segura); comparar por `.secret()` como arriba compila
porque `String`/`&str` sí tienen `PartialEq`. Si se quiere comparación en
tiempo constante habría que sumar esa feature o usar `constant_time_eq`.

## 3. Intercambio de código por tokens

```rust
use openidconnect::{AuthorizationCode, TokenResponse};

let token_response = client
    .exchange_code(AuthorizationCode::new(code))?      // <- Result<CodeTokenRequest, ConfigurationError>
    .request_async(&http_client)
    .await?;                                            // <- Result<CoreTokenResponse, RequestTokenError<...>>

let id_token = token_response
    .id_token()
    .ok_or(/* el IdP no devolvió id_token */)?;
```

Detalle de tipos verificado en fuente (`client.rs:1002`, variante que
aplica cuando el cliente se construyó con `from_provider_metadata`, que
ya trae `token_endpoint` seteado): `exchange_code` devuelve
`Result<CodeTokenRequest<TE, TR>, ConfigurationError>` (falla solo si no
hay `token_uri` configurada — no debería pasar viniendo de discovery).
`request_async` devuelve `Result<CoreTokenResponse, RequestTokenError<RE, TE>>`
con variantes (`oauth2-5.0.0/src/error.rs:112`): `ServerResponse(T)` (el
IdP devolvió un error OAuth), `Request(RE)` (fallo de red/HTTP), `Parse`
(respuesta no parseable), y alguna más — todas con `#[error(...)]` de
`thiserror`, que es la misma crate de errores que ya usa este repo.

PKCE es opcional en el ejemplo de la crate pero recomendado
(`PkceCodeChallenge::new_random_sha256()` al generar la URL,
`.set_pkce_verifier(verifier)` al intercambiar) — Google lo soporta.

## 4. Validar el ID token (firma JWKS, `aud`, `iss`, `exp`)

```rust
let id_token_verifier = client.id_token_verifier(); // -> IdTokenVerifier<CoreJsonWebKey>, SIN red
let claims = id_token.claims(&id_token_verifier, &nonce)?;
```

Confirmado en fuente que **`client.id_token_verifier()` no hace ninguna
llamada de red**: construye el verificador con `self.jwks.clone()` (el
JWKS que ya se descargó en el paso de discovery), más `client_id` e
`issuer` ya conocidos (`client.rs:642-663`). Si el cliente tiene
`client_secret` usa `IdTokenVerifier::new_confidential_client(...)`, si no
`::new_public_client(...)` — ambos constructores viven en
`openidconnect::IdTokenVerifier` (`src/verification/mod.rs`, no
inspeccionado línea por línea pero confirmado por firma en `client.rs`).
También aplica automáticamente `set_allowed_algs(...)` con los algoritmos
que el discovery doc anunció en `id_token_signing_alg_values_supported`.

Firma exacta (verificada en `src/id_token/mod.rs:113`):

```rust
pub fn claims<'a, K, N>(
    &'a self,
    verifier: &IdTokenVerifier<K>,
    nonce_verifier: N,
) -> Result<&'a IdTokenClaims<AC, GC>, ClaimsVerificationError>
where
    K: JsonWebKey<SigningAlgorithm = JS>,
    N: NonceVerifier;
```

`aud` se valida contra el `client_id` que se usó para construir el
verificador (el mismo `client_id` del `CoreClient`) — no hay que pasarlo
aparte. `iss` se valida contra el `issuer` que trae el `CoreClient` (el
mismo que devolvió discovery, ya validado ahí también). `exp` se valida
siempre.

**Errores** — `ClaimsVerificationError` (`#[non_exhaustive]`, 10
variantes, confirmado vía docs.rs 4.0.1):

| Variante | Cuándo |
|---|---|
| `Expired` | `exp` vencido |
| `InvalidAudience` | `aud` no coincide con el `client_id` |
| `InvalidIssuer` | `iss` no coincide |
| `SignatureVerification` | firma inválida / clave no encontrada en el JWKS |
| `InvalidNonce` | el `nonce` del token no coincide con el pasado a `claims()` |
| `InvalidSubject`, `InvalidAuthContext`, `InvalidAuthTime`, `Unsupported`, `Other` | casos menos comunes (multi-`aud` sin `azp`, `acr`, `auth_time`, alg no soportado, etc.) |

Es un solo enum para los tres casos que pide la tarea (firma / aud /
exp) — se puede diferenciar en el `match` para dar mensajes de error
tipados distintos si `docs/security-scope.md` lo exige.

Para forzar rechazo de tokens sin firma (alg `none`) u otros ataques
clásicos: por defecto la firma **sí se verifica** (`enable_signature_check`
es el estado por defecto; `insecure_disable_signature_check()` existe pero
hay que llamarlo explícitamente para desactivarlo — no hacerlo nunca en
producción).

**Ambigüedad menor no resuelta por lectura de fuente**: no confirmé el
comportamiento exacto de `require_issuer_match()`/`require_audience_match()`
cuando se llaman explícitamente (si son no-ops por ser ya default `true`,
o si existen variantes para relajarlos) — no debería hacer falta tocarlos
para el caso estándar de este Gateway, pero si el reviewer quiere
verificación extra estricta, están ahí (`IdTokenVerifier`, listados en
docs.rs).

## 5. Extraer `sub`, `email`, nombre

```rust
let sub: &str = claims.subject().as_str();                     // SubjectIdentifier
let email: Option<&str> = claims.email().map(|e| e.as_str());  // Option<&EndUserEmail>, NO localizado
let email_verified: Option<bool> = claims.email_verified();

// name/given_name/family_name SÍ están localizados (LocalizedClaim<T>):
let name: Option<&str> = claims
    .name()                                   // Option<&LocalizedClaim<EndUserName>>
    .and_then(|n| n.get(None))                // el valor sin locale (lo típico en Google)
    .map(|n| n.as_str());
let given_name = claims.given_name().and_then(|n| n.get(None)).map(|n| n.as_str());
let family_name = claims.family_name().and_then(|n| n.get(None)).map(|n| n.as_str());
```

Confirmado en `src/claims.rs`: `email`/`email_verified` son campos planos
(`Option<EndUserEmail>`, `Option<bool>`), mientras que `name`,
`given_name`, `family_name` (y `nickname`, `profile`, `picture`, etc.) son
`Option<LocalizedClaim<T>>`. `LocalizedClaim<T>` (`src/types/localized.rs`)
expone `.get(locale: Option<&LanguageTag>) -> Option<&T>` y
`.iter() -> impl Iterator<Item = (Option<&LanguageTag>, &T)>`. Google
normalmente manda estos claims sin locale (clave `None`), así que
`.get(None)` es la forma correcta y explícita de leerlos (más precisa que
iterar y tomar el primero, aunque ambas formas aparecen en ejemplos de la
comunidad).

## 6. Runtime y feature flags

- Requiere `tokio` como runtime async para el cliente asíncrono
  (`reqwest::Client` async) — el repo ya usa `tokio` con
  `rt-multi-thread` + `macros`, no hace falta agregar features de tokio
  por esto.
- `openidconnect = "4.0.1"` sin especificar features basta: trae
  `reqwest` + `rustls-tls` por defecto y **no** trae `native-tls`
  (confirmado en el `Cargo.toml` fuente de `oauth2` 5.0.0:
  `reqwest = { version = "0.12", optional = true, default-features =
  false }`, y la feature `rustls-tls = ["reqwest/rustls-tls"]` — no hay
  ninguna feature de TLS activada salvo la que se pide explícitamente).
  Esto es consistente con `lapin = { version = "2", features =
  ["rustls"], default-features = false }`, que ya usa el repo — mismo
  criterio de "rustls en todas partes" se cumple sin esfuerzo extra.
- Advertencia de seguridad de la propia crate (doc de `lib.rs`): el
  `reqwest::Client`/`reqwest::ClientBuilder` usado como `http_client` debe
  construirse con `.redirect(reqwest::redirect::Policy::none())` para
  evitar SSRF — esto aplica igual en producción (contra Google) y en los
  tests (contra el IdP local).

## Referencias

- crates.io: `https://crates.io/crates/openidconnect` (API JSON:
  `max_version = max_stable_version = newest_version = "4.0.1"`).
- docs.rs: `https://docs.rs/openidconnect/4.0.1/openidconnect/`.
- Fuente descargada y leída directamente:
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/openidconnect-4.0.1/src/{lib.rs,client.rs,discovery/mod.rs,claims.rs,id_token/mod.rs,types/localized.rs}`
  y `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/oauth2-5.0.0/src/{types.rs,error.rs,Cargo.toml}`.
- `docs/verification.md` de este repo (Nivel 3, sección `auth`) ya exige
  exactamente el patrón de IdP de prueba local con JWKS propio descrito
  aquí — este hallazgo confirma que es técnicamente viable con la crate
  tal cual, siempre que se resuelva el gap de configurabilidad del
  issuer en `src/config.rs` señalado en la sección 1.
