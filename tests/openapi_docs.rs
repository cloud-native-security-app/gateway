//! Tests de integración de la feature `openapi_docs`.
//!
//! No requieren Docker ni ningún servidor externo: solo generan la
//! especificación OpenAPI de [`gateway::api::ApiDoc`] (feature `openapi_docs`,
//! RNF-08) y la comparan contra [`gateway::api::ROUTES`] — la misma tabla
//! canónica que ya usa `tests/session_middleware_and_me.rs` para verificar
//! qué rutas llevan el middleware de sesión. Este es el mecanismo
//! anti-drift exigido por el criterio de aceptación 3: una ruta añadida a
//! `ROUTES`/`app_router` sin registrar su handler en
//! `#[openapi(paths(...))]` de `ApiDoc` queda ausente de la especificación
//! generada, y `route_is_documented_in_the_generated_openapi_spec` falla en
//! vez de dejar documentación desactualizada en silencio.

use gateway::api::{ApiDoc, ROUTES};
use utoipa::OpenApi;

/// Traduce un path con la sintaxis de parámetro de `axum`/`matchit`
/// (`:scan_id`) a la sintaxis de parámetro de OpenAPI (`{scan_id}`), la que
/// usan los atributos `path = "..."` de cada `#[utoipa::path(...)]` en
/// `src/api.rs`.
fn to_openapi_path(axum_path: &str) -> String {
    axum_path
        .split('/')
        .map(|segment| match segment.strip_prefix(':') {
            Some(param_name) => format!("{{{param_name}}}"),
            None => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Genera la especificación OpenAPI y la deserializa de vuelta desde su JSON
/// serializado, tal como haría un cliente real de `GET /api/openapi.json`
/// (ver `gateway::api::openapi_json`) — no se inspecciona directamente el
/// árbol de tipos de `utoipa` en memoria, para que este test verifique lo
/// mismo que un consumidor externo vería.
fn generated_spec_as_json() -> serde_json::Value {
    let openapi = ApiDoc::openapi();
    let raw = serde_json::to_string(&openapi).expect("la especificación debe serializar a JSON");
    serde_json::from_str(&raw).expect("el JSON serializado debe ser JSON válido")
}

#[test]
fn generated_spec_is_valid_json_with_the_expected_openapi_shape() {
    let spec = generated_spec_as_json();

    assert!(
        spec.get("openapi").is_some(),
        "la especificación debe declarar la versión de OpenAPI"
    );
    assert!(
        spec.get("info").is_some(),
        "la especificación debe incluir un bloque `info`"
    );
    assert!(
        spec.get("paths")
            .and_then(|paths| paths.as_object())
            .is_some(),
        "la especificación debe incluir un objeto `paths`"
    );
}

/// Criterio de aceptación 1/3/4 de la feature `openapi_docs`: toda ruta
/// pública listada en [`ROUTES`] (la tabla canónica de `app_router`, fuente
/// única de verdad ya establecida por la feature `session_middleware_and_me`)
/// tiene una operación correspondiente (mismo path traducido a la sintaxis
/// de OpenAPI, mismo método HTTP) en la especificación generada por
/// [`ApiDoc`]. Una ruta nueva que se añada a `ROUTES` sin anotar su handler
/// con `#[utoipa::path(...)]` y registrarlo en `ApiDoc` hace fallar este
/// test, en vez de quedar documentada solo a medias en silencio.
#[test]
fn every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec() {
    let spec = generated_spec_as_json();
    let paths = spec
        .get("paths")
        .and_then(|paths| paths.as_object())
        .expect("la especificación debe incluir un objeto `paths`");

    // Varios métodos de `ROUTES` pueden compartir el mismo `path` de OpenAPI
    // (p. ej. `GET`/`POST /api/scans` conviven en el mismo `PathItem`), así
    // que se compara contra el número de *paths* distintos esperados, no
    // contra `ROUTES.len()` directamente.
    let expected_paths: std::collections::BTreeSet<String> = ROUTES
        .iter()
        .map(|route| to_openapi_path(route.path))
        .collect();
    assert_eq!(
        paths
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_paths,
        "la especificación OpenAPI debe listar exactamente los paths de ROUTES, ni más ni menos \
         (un path de más sugiere una anotación huérfana; uno de menos, una ruta sin documentar)"
    );

    for route in ROUTES {
        let openapi_path = to_openapi_path(route.path);
        let path_item = paths.get(&openapi_path).unwrap_or_else(|| {
            panic!(
                "la especificación OpenAPI no documenta la ruta {} {} (path traducido: {openapi_path}); \
                 falta anotar su handler con #[utoipa::path(...)] y registrarlo en ApiDoc",
                route.method, route.path
            )
        });

        let method_key = route.method.to_ascii_lowercase();
        assert!(
            path_item.get(&method_key).is_some(),
            "la especificación OpenAPI documenta {openapi_path} pero no el método {} \
             (definido en ROUTES para {})",
            route.method,
            route.path
        );
    }
}
