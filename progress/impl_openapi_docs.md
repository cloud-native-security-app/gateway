# Implementación — feature 10: openapi_docs

## Archivos creados/modificados

- `Cargo.toml`: añade `utoipa = { version = "5.5.0", features = ["axum_extras"] }`
  (con comentario explicando la decisión de no añadir `utoipa-swagger-ui`).
  `Cargo.lock` actualizado en consecuencia.
- `src/api.rs`:
  - Añade `#[utoipa::path(...)]` sobre los 10 handlers existentes
    (`login`, `callback`, `logout`, `health`, `me`, `profile`, `submit_scan`,
    `list_scan_history`, `scan_events`, `cancel_scan`), reutilizando los
    doc-comments `///` ya existentes de cada uno (utoipa toma
    summary/description automáticamente de los comentarios de rustdoc, no
    se escribió texto nuevo salvo las descripciones de cada código de
    respuesta HTTP, que no existían como texto en rustdoc).
  - `#[derive(utoipa::ToSchema)]` en `MeResponse`, `ScanSubmissionRequest`,
    `ScanSubmissionResponse`, `ScanHistoryEntryResponse` (todas privadas al
    módulo, no rompe `#![deny(missing_docs)]` de `src/lib.rs`).
  - `#[derive(utoipa::IntoParams)]` en `CallbackParams` (query params de
    `GET /auth/callback`).
  - Nueva ruta pública `GET /api/openapi.json` (handler `openapi_json`,
    función `openapi_router()`, mergeada en `app_router` fuera del
    middleware de sesión — mismo patrón que `health_router`) y su entrada
    correspondiente en la tabla `ROUTES` (`protected: false`).
  - `SessionCookieSecurity` (`impl utoipa::Modify`): registra el
    `securitySchemes.session_cookie` (`apiKey`, `in: cookie`, `name =
    gateway::auth::SESSION_COOKIE_NAME`) referenciado por cada ruta
    protegida vía `security(("session_cookie" = []))`.
  - `ApiDoc` (`#[derive(utoipa::OpenApi)]`): agrega los 11 `paths(...)`
    (los 10 handlers existentes + `openapi_json`), los `components(schemas(...))`
    de los tipos de arriba + `usuarios_client::ScanStatus`, 5 `tags` y el
    `modifiers(&SessionCookieSecurity)`.
- `src/usuarios_client.rs`: `#[derive(utoipa::ToSchema)]` en `ScanStatus`
  (aparece como campo de `ScanHistoryEntryResponse` en el schema generado).
  `UserProfile` (alias de `serde_json::Value`) no necesitó cambios: `utoipa`
  ya implementa `ToSchema`/`PartialSchema` para `serde_json::Value` en el
  propio crate base.
- `tests/openapi_docs.rs` (nuevo): ver sección de test anti-drift abajo.

## Decisión: sin `utoipa-swagger-ui`

El criterio de aceptación 2 solo exige que `GET /api/openapi.json` sirva el
JSON generado, no una UI interactiva. Añadir `utoipa-swagger-ui` habría sido
una dependencia más sin un criterio de aceptación que la exija — se deja
fuera por ahora (sobre-ingeniería no pedida), documentado en el comentario de
`Cargo.toml` junto a la dependencia de `utoipa`.

## Diseño del test anti-drift (criterio de aceptación 3)

`tests/openapi_docs.rs` sigue el mismo patrón que la tabla `ROUTES` ya usada
en `tests/session_middleware_and_me.rs` (feature 4):

1. `generated_spec_as_json()` construye `ApiDoc::openapi()`, la serializa a
   JSON con `serde_json` y la vuelve a parsear — exactamente lo que vería un
   cliente real de `GET /api/openapi.json`, no una inspección directa del
   árbol de tipos de `utoipa` en memoria.
2. `to_openapi_path()` traduce la sintaxis de parámetro de `axum`/`matchit`
   (`:scan_id`) a la de OpenAPI (`{scan_id}`), la misma que usan los
   atributos `path = "..."` de cada `#[utoipa::path(...)]`.
3. `every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`
   compara el conjunto de `paths` de la especificación generada contra el
   conjunto de paths traducidos desde `gateway::api::ROUTES`, y además
   verifica, por cada entrada de `ROUTES`, que el método HTTP concreto
   (`get`/`post`) está presente en el `PathItem` de ese path.

Verifiqué manualmente que el mecanismo detecta drift: inserté temporalmente
una entrada falsa en `ROUTES` (`GET /api/undocumented-drift-check`, sin
handler anotado ni registrado en `ApiDoc`) y confirmé que
`every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`
falla con un mensaje explícito; luego revertí el cambio y confirmé que la
suite vuelve a pasar en verde. Esto es el criterio de aceptación 3
demostrado, no solo afirmado.

`generated_spec_is_valid_json_with_the_expected_openapi_shape` cubre el
criterio de aceptación 4 (JSON válido con la forma esperada de OpenAPI:
`openapi`, `info`, `paths`).

## Verificación de cada criterio de aceptación

1. **Toda ruta pública tiene su anotación OpenAPI con request/response
   documentados**: las 10 rutas preexistentes + la nueva
   `GET /api/openapi.json` llevan `#[utoipa::path(...)]`. Volqué la
   especificación generada a un archivo temporal (`cargo run --example`
   descartable, eliminado tras la inspección — no quedó en el repo) y
   confirmé a mano que cada path/método tiene `summary` (del doc-comment),
   `responses` con descripción por código, y `schema`/`requestBody` donde
   corresponde (`MeResponse`, `UserProfile`, `ScanSubmissionRequest`/
   `ScanSubmissionResponse`, `[ScanHistoryEntryResponse]`). La limitación de
   SSE (`GET /api/scans/{scan_id}/events`, sin schema estructurado por
   evento) queda documentada explícitamente en el doc-comment del handler.
2. **`GET /api/openapi.json` pública sirve la especificación generada**:
   implementado (`openapi_router`, fuera del middleware de sesión, con
   entrada `protected: false` en `ROUTES`, verificada indirectamente por
   `tests/session_middleware_and_me.rs::enumerates_routes_and_verifies_which_carry_the_session_middleware`,
   que sigue en verde con la nueva entrada).
3. **Ruta nueva sin anotación hace fallar un test**: demostrado
   manualmente (ver arriba) con `tests/openapi_docs.rs`.
4. **Test verifica JSON válido + lista todas las rutas públicas
   esperadas**: `tests/openapi_docs.rs` (dos tests, ver arriba).

## Resultado de los comandos de verificación

- `cargo build`: OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings`: OK, sin advertencias.
- `cargo fmt --check`: OK (tras `cargo fmt`).
- `cargo doc --no-deps`: OK, sin warnings (se corrigió un
  `rustdoc::private_intra_doc_links` al enlazar `[`openapi_json`]`, un ítem
  privado, desde el doc-comment de módulo — se cambió el enlace a
  `[`openapi_router`]`, que sí es público).
- `cargo test` (sin `--ignored`): 54 tests unitarios + todos los tests de
  integración no marcados `#[ignore]` en verde, incluidos los 2 nuevos de
  `tests/openapi_docs.rs`. Ninguna feature 1-9 se rompió.
- `cargo test -- --ignored` (Docker disponible en este entorno): los 3 tests
  marcados `#[ignore = "requiere Docker"]` (broker real vía
  `testcontainers`) también pasan.
- `./init.sh`: termina con `[OK] Entorno listo.`, exit code 0.

## Dudas/bloqueos

Ninguno. La feature no tocó lógica de negocio de login/sesión/Broker (solo
la documentó vía anotaciones declarativas), así que no fue necesario
modificar `src/auth.rs`, `src/broker.rs`, ni el manejo de credenciales — se
leyó `docs/security-scope.md` de todas formas antes de tocar `src/api.rs`
por precaución (las rutas anotadas incluyen login/callback/sesión), y se
confirmó que la única referencia a un dato sensible en la documentación
generada es el *nombre* de la cookie de sesión (`gateway_session`) en el
`securityScheme`, nunca su valor/firma — no hay secreto expuesto.

No se marcó la feature como `done` ni se movió progreso a `history.md`: eso
es responsabilidad del `reviewer` y del `leader`, según el protocolo.
