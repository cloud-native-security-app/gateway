# Exploración: IdP OIDC de prueba en memoria para tests de `auth`/`oidc_login`

> Pregunta: patrón idiomático Rust/axum/tokio para levantar, en un test de
> integración (`tests/`), un servidor HTTP en memoria que actúe como IdP
> OIDC de prueba (discovery + JWKS + token endpoint con ID tokens firmados
> y claims controlables).

## 0. Coherencia con lo que el repo ya documenta

- `docs/conventions.md` (líneas 26-30, 74-76) y `docs/verification.md`
  (líneas 47-53) **ya prescriben exactamente este patrón** para
  `usuarios_client` y para `auth`: un servidor HTTP de test *real*
  ("escuchando en un puerto — no una interceptación a nivel de módulo"),
  nunca un mock del protocolo, nunca el servicio de producción (Google en
  este caso). Para `auth` lo dice explícito: *"servidor HTTP de test que
  sirve un JWKS y tokens firmados con una clave de prueba (nunca contra el
  endpoint real de Google en el test suite)"*.
- `docs/architecture.md` (líneas 27-32, 121-123) fija las crates:
  `openidconnect` para el handshake/validación del lado del **cliente**
  (Gateway), `jsonwebtoken` para la sesión propia. Ninguna de las dos trae
  utilidades de *testing/mock* propias (confirmado abajo, §3) — el IdP de
  prueba se construye a mano.
- **Ambigüedad detectada, no resuelta por mí (leader/humano debe decidir):**
  `docs/verification.md` línea 57 dice *"Todo test de esta categoría
  [Nivel 3, que incluye `auth`] se marca `#[ignore = "requiere Docker"]`"*,
  pero las líneas 47-53 del mismo documento describen el test de `auth`
  contra un servidor HTTP en memoria (sin Docker), y `feature_list.json`
  (id=3, último criterio de aceptación) dice explícitamente que estos tests
  pueden ser *"un servidor HTTP de test en memoria [si no usan contenedor]"*
  sin exigir `#[ignore]`. Interpretación más consistente con el resto del
  documento: la frase "todo test de esta categoría" en verification.md se
  refiere a los que **sí** dependen de Docker (`broker`, `api` end-to-end
  vía RabbitMQ real); el test de `auth` con IdP en memoria no depende de
  Docker y por tanto **no** debería llevar `#[ignore]` — coincide con
  `usuarios_client`, que tampoco lo lleva. El implementer/reviewer debería
  confirmar esta lectura antes de cerrar la feature.

## 1. Recomendación de crates (dev-dependencies)

Ninguna de estas está hoy en `Cargo.toml`/`Cargo.lock` — hay que añadirlas.
Versiones vigentes en crates.io a 2026-09-19:

| Crate | Versión | Rol |
|---|---|---|
| `jsonwebtoken` | `11.1.0` (ya elegida por el repo para la sesión propia — **reusar la misma**, no introducir una segunda librería de firma tipo `jwt_simple`) | Firmar el ID token de prueba (`encode`) y construir el JWKS (módulo `jwk`: `Jwk`, `JwkSet`, `RSAKeyParameters`, `AlgorithmParameters::RSA`, `CommonParameters`) |
| `rsa` | `0.9.10` | Generar el par de claves RSA de prueba (`RsaPrivateKey::new`), exportar a PEM (PKCS1) para `EncodingKey::from_rsa_pem`, y extraer `n`/`e` para el JWKS |
| `rand` | `0.8` (la que pida `rsa` 0.9.x — revisar compatibilidad exacta en `cargo add`) | RNG para `RsaPrivateKey::new` |
| `base64` | `0.22` | Codificar `n`/`e` en base64url sin padding para el JWK |
| `axum` | ya en `[dependencies]` (`0.7`) | Montar el router del IdP de prueba (recomendado, ver §4) |
| `tokio` | ya en `[dependencies]` | `TcpListener` efímero + `axum::serve` + `tokio::spawn` |
| `serde_json` | ya en `[dependencies]` | Documento de discovery |

**No se necesita `wiremock`** como dependencia nueva si se opta por el
patrón axum-nativo (ver §4) — evita introducir una segunda forma de servir
HTTP de test en un repo que ya depende de `axum`, coherente con la regla de
"homogeneidad extrema" de `docs/conventions.md`. `wiremock` (última
`0.6.5`) es una alternativa idiomática y muy usada en el ecosistema, pero
su ventaja (matching declarativo de requests) no ahorra código aquí: el
endpoint `/token` necesita devolver un JWT *distinto por escenario de test*
(aud incorrecta / expirado / firma con otra clave), lo que en wiremock
obliga a implementar el trait `Respond` a mano (equivalente en líneas a un
handler de axum) o a montar un `Mock` nuevo por test con el JWT ya
pre-firmado embebido en el `ResponseTemplate::new(200).set_body_json(...)`
— esto último sí es más simple que un handler axum si el JWT se firma
*antes* de montar el mock. Ambos enfoques son válidos; se documenta el
axum-nativo como recomendación principal por no añadir dependencia y el de
wiremock como alternativa en §5.

**Nada en `openidconnect` (`4.0.1`) ayuda a mockear el lado servidor**: es
puramente un cliente OIDC (construye `CoreProviderMetadata`, valida
`IdToken`, etc.) — no trae un IdP embebido ni helpers de testing. Sí es
útil en el propio test para verificar que el *cliente* de `auth.rs`
descubre correctamente los endpoints apuntando al IdP de prueba (se le
pasa la URL de discovery del servidor en memoria en vez de la de Google
codificada a mano — el cliente OIDC de `auth.rs` no debe hardcodear la URL
de Google, debe ser configurable, precisamente para que el test pueda
apuntarlo al servidor de prueba).

## 2. Generar el par de claves RSA y el JWKS

```rust
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use rsa::pkcs1::LineEnding;
use jsonwebtoken::jwk::{Jwk, JwkSet, AlgorithmParameters, RSAKeyParameters, RSAKeyType,
                         CommonParameters, PublicKeyUse, KeyAlgorithm};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

struct TestIdpKey {
    kid: String,
    private_pem: String, // PKCS1 "RSA PRIVATE KEY" — aceptado por EncodingKey::from_rsa_pem
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestIdpKey {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen de prueba");
    let pub_key = RsaPublicKey::from(&priv_key);

    let private_pem = priv_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("pem de prueba")
        .to_string();

    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };

    TestIdpKey { kid: kid.to_string(), private_pem, jwk }
}

fn jwks_document(keys: &[TestIdpKey]) -> JwkSet {
    JwkSet { keys: keys.iter().map(|k| k.jwk.clone()).collect() }
}
```

(`RSAKeyType`/campos exactos de `CommonParameters` confirmar contra
`docs.rs/jsonwebtoken/11.1.0/jsonwebtoken/jwk` al implementar — la API
pública verificada son los structs/enums `Jwk`, `JwkSet`, `CommonParameters`,
`RSAKeyParameters`, `AlgorithmParameters`, `KeyAlgorithm`, `PublicKeyUse`;
`RSAKeyParameters` tiene exactamente `key_type: RSAKeyType`, `n: String`,
`e: String`.)

## 3. Firmar el ID token con claims controlables

```rust
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use serde::Serialize;

#[derive(Serialize)]
struct TestIdTokenClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    email: &'a str,
    name: &'a str,
    exp: i64,
    iat: i64,
}

fn sign_id_token(key: &TestIdpKey, claims: &TestIdTokenClaims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let encoding_key = EncodingKey::from_rsa_pem(key.private_pem.as_bytes())
        .expect("pem de prueba válido");
    encode(&header, claims, &encoding_key).expect("firma de prueba")
}
```

Variantes que pide `feature_list.json` (id=3, último criterio) salen de
tocar estos mismos parámetros sin cambiar la infraestructura del servidor:

- **`aud` incorrecta**: `aud: "otro-client-id"` en vez del `client_id` que
  usa el `auth.rs` bajo test.
- **Expirado**: `exp: (Utc::now() - Duration::minutes(5)).timestamp()`.
- **Firma inválida**: firmar con un `TestIdpKey` distinto (segundo
  keypair) al publicado en el JWKS que sirve el mismo servidor de prueba —
  o publicar en el JWKS solo la clave "buena" pero firmar con la "mala"
  (mismo `kid` a propósito, para probar que `auth.rs` valida la firma
  criptográfica y no solo hace *lookup* por `kid`).
- **`state` ausente/incorrecto**: esto no toca el IdP de prueba — se
  ejerce llamando `GET /auth/callback` del propio Gateway sin el parámetro
  `state` o con uno que no coincide con el emitido por `/auth/login`; no
  requiere tocar el servidor mock.

## 4. Montar el IdP de prueba: axum efímero (recomendado)

```rust
use axum::{routing::get, Router, extract::State, Json};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::{Arc, Mutex}};
use tokio::net::TcpListener;

#[derive(Clone)]
struct TestIdpState {
    jwks: Arc<JwkSet>,
    // El test controla qué token devuelve /token por escenario:
    next_token: Arc<Mutex<String>>,
}

async fn discovery(State(st): State<TestIdpState>, base: String) -> Json<Value> {
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks(State(st): State<TestIdpState>) -> Json<JwkSet> {
    Json((*st.jwks).clone())
}

async fn token(State(st): State<TestIdpState>) -> Json<Value> {
    let id_token = st.next_token.lock().unwrap().clone();
    Json(json!({
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "id_token": id_token,
    }))
}

async fn spawn_test_idp(jwks: JwkSet) -> (SocketAddr, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let next_token = Arc::new(Mutex::new(String::new()));
    let state = TestIdpState { jwks: Arc::new(jwks), next_token: next_token.clone() };

    let base = format!("http://{addr}");
    let app = Router::new()
        .route("/.well-known/openid-configuration",
               get(move |s| discovery(s, base.clone())))
        .route("/jwks", get(jwks))
        .route("/token", get(token).post(token))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, next_token)
}
```

Uso en el test (pseudocódigo, integración con `auth.rs`):

```rust
#[tokio::test]
async fn accepts_valid_id_token_and_creates_session() {
    let key = generate_test_key("test-kid-1");
    let jwks = jwks_document(&[key /* ...clonar según necesidad... */]);
    let (addr, next_token) = spawn_test_idp(jwks).await;

    let claims = TestIdTokenClaims {
        iss: &format!("http://{addr}"),
        aud: TEST_CLIENT_ID,
        sub: "google-sub-123",
        email: "user@example.com",
        name: "Test User",
        exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
    };
    *next_token.lock().unwrap() = sign_id_token(&key, &claims);

    // construir el cliente auth.rs apuntando el discovery a http://{addr}/.well-known/openid-configuration
    // en vez de la URL de Google (config inyectable, no hardcodeada)
    // ejercer GET /auth/login -> GET /auth/callback?code=...&state=...
    // aserciones: 302/200, cookie Set-Cookie con HttpOnly+Secure+SameSite=Strict presente,
    // contenido de la sesión (sub/email/name) correcto.
}
```

Nota clave de diseño para `auth.rs` (no lo decide esta exploración, pero
condiciona si el test es viable): el discovery URL / issuer de Google debe
ser **configurable** (vía `Config`, no una constante hardcodeada apuntando
a `accounts.google.com`), exactamente igual que `usuarios_client` no
hardcodea la URL de `ms-usuarios`. Si el código de producción hardcodea el
endpoint de Google, este patrón de test no puede apuntar el cliente OIDC
al servidor en memoria y la feature queda bloqueada — bloqueo a reportar
al implementer, no a resolver aquí.

## 5. Alternativa con `wiremock` (viable, no recomendada por defecto)

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

let mock_server = MockServer::start().await; // puerto efímero automático

Mock::given(method("GET")).and(path("/.well-known/openid-configuration"))
    .respond_with(ResponseTemplate::new(200).set_body_json(discovery_json(&mock_server.uri())))
    .mount(&mock_server).await;

Mock::given(method("GET")).and(path("/jwks"))
    .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
    .mount(&mock_server).await;

// El id_token depende del escenario -> se firma ANTES de montar el mock
// para ese test concreto (o se usa un Respond custom si se quiere una
// única ruta que varíe por request).
Mock::given(method("POST")).and(path("/token"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "id_token": sign_id_token(&key, &claims),
    })))
    .mount(&mock_server).await;
```

Ventaja: menos código de infraestructura (no hay que escribir handlers
axum). Desventaja frente a §4: introduce una dependencia nueva que no
comparte código/patrón con el resto del repo (que ya usa axum para todo lo
que es "servidor HTTP"), y cada variante de escenario exige remontar
mocks o usar `Respond` custom (complejidad similar a un handler axum).
Usar si el equipo prioriza brevedad de test sobre no añadir dependencias;
si no, preferir §4.

## 6. Limitaciones / puntos abiertos para el implementer

1. **Confirmar `#[ignore]` o no** para este test de `auth` — ver ambigüedad
   documentada en §0. Recomendación: no ignorarlo (corre en `cargo test`
   sin flags), igual que `usuarios_client`.
2. `EncodingKey::from_rsa_pem` requiere el feature `use_pem` de
   `jsonwebtoken` (verificar que esté activo; suele venir por defecto en
   `jsonwebtoken` moderno, pero confirmar en `Cargo.toml` al añadir la
   dependencia).
3. `rsa::RsaPrivateKey::new` con 2048 bits tarda un rato notable en debug
   sin optimizaciones (segundos, no milisegundos) — considerar generar la
   clave una sola vez por proceso de test (`once_cell`/`std::sync::OnceLock`
   estático) si varios tests de `auth` la necesitan, para no penalizar
   `cargo test` completo. No es bloqueante pero afecta "RNF" de velocidad
   de la suite.
4. No verifiqué en el código fuente real de `jsonwebtoken` 11.1.0 (solo en
   su documentación renderizada vía WebFetch) el nombre exacto de todos los
   campos de `CommonParameters`; al implementar, correr
   `cargo doc --open -p jsonwebtoken` o revisar el struct en
   `~/.cargo/registry` para no adivinar campos no confirmados.
5. `openidconnect` 4.0.1: no confirmé en detalle su API de configuración
   de discovery URL custom (se asume que expone algo tipo
   `CoreProviderMetadata::discover_async(IssuerUrl::new(...), http_client)`
   donde `IssuerUrl` es arbitraria) — eso es objeto de la exploración
   paralela sobre la API de `openidconnect` (explorer #1 según
   `progress/current.md`), no de esta.
