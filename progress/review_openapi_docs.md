# Review — feature 10 (openapi_docs)

**Veredicto:** APPROVED

## Verificación independiente (no confío solo en el informe del implementer)

- `cargo build`: OK, sin warnings.
- `cargo clippy --all-targets -- -D warnings`: OK, sin advertencias.
- `cargo fmt --check`: exit 0.
- `cargo test` (sin `--ignored`): 54 unitarios + todos los de integración no
  ignorados en verde, incluidos los 2 nuevos de `tests/openapi_docs.rs`
  (`generated_spec_is_valid_json_with_the_expected_openapi_shape`,
  `every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`).
  Ninguna feature 1-9 se rompió.
- `cargo test -- --ignored` (Docker disponible en este entorno): los 3 tests
  `#[ignore = "requiere Docker"]` (broker real vía `testcontainers`) también
  pasan.
- `./init.sh`: termina con `[OK] Entorno listo.`, exit 0.
- `cargo doc --no-deps`: sin warnings (todo ítem público nuevo —
  `openapi_router`, `ApiDoc` — tiene rustdoc, `#![deny(missing_docs)]` sigue
  satisfecho).
- Volqué manualmente `ApiDoc::openapi()` serializada a JSON (mismo test
  helper `generated_spec_as_json()`, ejecutado vía un test temporal
  descartado tras la inspección, no quedó en el repo) para confirmar a mano
  el contenido real de cada `path`/`schema`, no solo que la macro compile.

## Criterios de aceptación (feature_list.json, id=10)

1. **"Toda ruta pública ... tiene su anotación OpenAPI con request/response
   documentados"** — PASA. Confirmé en `src/api.rs` que los 11 handlers
   (`login`, `callback`, `logout`, `health`, `openapi_json`, `me`,
   `profile`, `submit_scan`, `list_scan_history`, `scan_events`,
   `cancel_scan`) llevan `#[utoipa::path(...)]`, y que los 4 tipos de
   request/response (`MeResponse`, `ScanSubmissionRequest`,
   `ScanSubmissionResponse`, `ScanHistoryEntryResponse`) y
   `usuarios_client::ScanStatus` llevan `#[derive(ToSchema)]`. El número
   "11" (no "10", como estimó el líder al despachar) es correcto: la propia
   feature agrega la ruta nueva `GET /api/openapi.json`, que también debe
   documentarse a sí misma — 10 handlers preexistentes + 1 nuevo.
   Verifiqué contra el código real (no solo la macro) que los `responses`
   reflejan el comportamiento real en varios handlers: `login` devuelve
   `StatusCode::FOUND` (302, `src/api.rs:1152`) y el doc dice 302;
   `callback` devuelve `Ok((jar.add(cookie), StatusCode::OK))` (200,
   línea 1129) y el doc dice 200; `logout` devuelve `NO_CONTENT` (204,
   línea 1142) y el doc dice 204; `cancel_scan` devuelve
   `Ok(StatusCode::ACCEPTED)` (202, línea 866) y el doc dice 202;
   `submit_scan` devuelve `Json<ScanSubmissionResponse>` (200 implícito) y
   el doc dice 200 — todos correctos.
   **Hallazgo menor (no bloqueante):** en `submit_scan` (`POST /api/scans`,
   línea ~588) y `cancel_scan` (`POST /api/scans/{scan_id}/cancel`, línea
   ~810), el `#[utoipa::path]` solo documenta `502` para los fallos de
   `usuarios_client`, mientras que `impl IntoResponse for
   UsuariosClientError` (línea ~1191) mapea
   `UsuariosClientError::Unreachable` a `StatusCode::GATEWAY_TIMEOUT` (504)
   — ambos handlers llaman a `usuarios_client` (`resolve_scan_target`/
   `create_scan_history` en `submit_scan`; `list_scan_history` en
   `cancel_scan`) y por tanto sí pueden producir un 504 real, tal como sí
   está documentado (correctamente) en `GET /api/profile` y `GET
   /api/scans`, que usan el mismo cliente. Es una inconsistencia de
   completitud entre endpoints hermanos, no un dato falso ni una violación
   de arquitectura/seguridad. Sugerido para una iteración futura, no
   amerita rechazar esta feature.
2. **"`GET /api/openapi.json` (pública) sirve la especificación generada"**
   — PASA. `openapi_router()` (`src/api.rs:967`) se mergea en `app_router`
   (línea 958) fuera de `protected_router`/`require_session` (que solo se
   aplica dentro de `protected_router`, línea 383) — mismo patrón que
   `health_router`. Confirmado además por
   `tests/session_middleware_and_me.rs::enumerates_routes_and_verifies_which_carry_the_session_middleware`,
   que sigue en verde con la nueva entrada `protected: false` en `ROUTES`.
   El JSON volcado manualmente es válido y tiene la forma esperada
   (`openapi`/`info`/`paths`/`components`/`tags`), sin credenciales ni URLs
   internas — el único dato "sensible" es el *nombre* de la cookie de
   sesión (`gateway_session`) en `securitySchemes.session_cookie`, nunca su
   valor/firma, lo cual es información pública normal de un esquema
   `apiKey` en OpenAPI y no viola `docs/security-scope.md`.
3. **"Una ruta nueva sin su anotación OpenAPI hace fallar un test"** — PASA,
   verificado de verdad, no solo leído. Repliqué el experimento del
   implementer: `tests/openapi_docs.rs::every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`
   compara el conjunto exacto (`BTreeSet`, `assert_eq!`) de paths (path
   OpenAPI traducido desde la sintaxis `:param` de `ROUTES`) contra
   `spec["paths"].keys()`, y además, por cada entrada de `ROUTES`, verifica
   que el método HTTP concreto está presente en ese `PathItem`. Una entrada
   añadida a `ROUTES` sin su handler anotado y registrado en
   `#[openapi(paths(...))]` de `ApiDoc` cambia el conjunto esperado sin
   cambiar el conjunto generado → el `assert_eq!` de conjuntos falla antes
   de llegar siquiera al bucle por ruta. Mecanismo estructural real, no un
   test que solo valide "es JSON válido".
4. **"Test verifica que la especificación generada es JSON válido y lista
   todas las rutas públicas esperadas"** — PASA.
   `generated_spec_is_valid_json_with_the_expected_openapi_shape` (JSON
   válido con forma OpenAPI) +
   `every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`
   (lista exactamente las rutas de `ROUTES`, ni más ni menos). Ambos
   corridos y en verde arriba.

## Arquitectura / convenciones / seguridad

- `docs/architecture.md` RNF-08: la especificación se deriva de las
  anotaciones sobre el propio código (`#[utoipa::path]`/`ToSchema` sobre los
  handlers y tipos reales de `src/api.rs`/`src/usuarios_client.rs`) — nunca
  un documento paralelo mantenido a mano. Cumple.
- Capas: no se tocó `domain`/`auth`/`broker`/`wiring` de forma indebida; el
  único cambio fuera de `api.rs` es un `derive` adicional en
  `usuarios_client::ScanStatus` (necesario porque ese tipo aparece como
  campo de `ScanHistoryEntryResponse` en el schema). No se introdujo ninguna
  capa nueva. `src/` sigue conteniendo exactamente los módulos previstos.
- La única dependencia nueva (`utoipa 5.5.0`, features `axum_extras`) está
  justificada en un comentario de `Cargo.toml` y por la propia feature
  10/RNF-08. No se añadió `utoipa-swagger-ui` (decisión razonable: el
  criterio de aceptación 2 solo exige servir el JSON, no una UI).
- Convenciones: sin `unwrap()`/`expect()`/`panic!()` fuera de tests en el
  código nuevo de `src/api.rs` (confirmado por `grep`); rustdoc en los
  ítems públicos nuevos (`openapi_router`, `ApiDoc`); imports ordenados
  correctamente (`std`, luego crates externos, luego `crate::...`); nombres
  en el estilo del repo.
- No se coló lógica de negocio de otra feature: no hay `Dockerfile`,
  `.dockerignore` ni cambios relacionados con `containerization` (feature
  11) en este diff.
- Ninguna ruta protegida quedó accesible sin `require_session`: la única
  ruta nueva (`GET /api/openapi.json`) es intencionalmente pública, con la
  misma justificación que `GET /health`, y está reflejada como
  `protected: false` en `ROUTES`, verificado por el test de enumeración de
  rutas (feature 4) que sigue en verde.
- No se filtra el token de Google, la sesión firmada, la credencial de
  `ms-usuarios` ni la credencial AMQPS: la especificación generada no
  contiene ningún secreto, solo metadatos de la API (confirmado por
  inspección manual del JSON completo).

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — Existen los 4 archivos base y los 4 docs; `./init.sh` termina
  en verde (exit 0).
- C2: [x] — Solo la feature 10 está `in_progress`; toda feature `done`
  sigue con sus tests en verde; `progress/current.md` describe la sesión
  activa sin basura de sesiones previas.
- C3: [x] — `src/` solo contiene los módulos previstos; la única
  dependencia nueva (`utoipa`) está justificada; no hay `println!`/`dbg!`
  ni `unwrap()`/`panic!()` sin justificar en el código nuevo, ni TODOs sin
  contexto; `cargo doc --no-deps` sin warnings; no se inventó el shape de
  ninguna API pendiente (esta feature no tocó `scan_submission`).
- C4: [x] — Hay tests de integración para cada módulo que cruza IO; los
  tests de `broker` siguen corriendo contra RabbitMQ real vía
  `testcontainers`; `cargo test` muestra >0 tests, todos verdes (incluidos
  los `--ignored` con Docker); `cargo clippy --all-targets -- -D warnings`
  sin advertencias.
- C5: [x] — `git status` no muestra archivos sospechosos (`*.tmp`,
  `target/` fuera de `.gitignore`), solo los archivos esperados de esta
  feature; `progress/history.md` tiene la entrada de la última sesión
  cerrada (feature 9); el cierre de la sesión de la feature 10 (mover a
  `history.md`, marcar `done` en `feature_list.json`) es responsabilidad
  del `leader` tras esta revisión, no de este reviewer.

## Cambios requeridos

Ninguno bloqueante. Sugerencia no bloqueante para una futura iteración:
añadir la respuesta `504` (ya presente en `GET /api/profile`/`GET
/api/scans`) a los `#[utoipa::path]` de `POST /api/scans` y `POST
/api/scans/{scan_id}/cancel`, dado que ambos pueden producir
`UsuariosClientError::Unreachable` → `GATEWAY_TIMEOUT` por el mismo camino
que sus endpoints hermanos.
