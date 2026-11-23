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

/// Feature `admin-role-guard`: `GET /api/me` documenta el campo `role`
/// (`user`/`admin`) para que `front` pueda mostrar u ocultar el acceso de
/// administración.
#[test]
fn me_response_schema_documents_the_role_field() {
    let spec = generated_spec_as_json();
    let me = &spec["components"]["schemas"]["MeResponse"];
    assert!(
        me["properties"]["role"].is_object(),
        "MeResponse debe declarar `role`: {me}"
    );
    let role = &spec["components"]["schemas"]["Role"];
    assert_eq!(role["enum"], serde_json::json!(["user", "admin"]));
}

/// Feature `admin_realtime_feed`: las rutas de administración documentan sus
/// respuestas de autorización y los esquemas del snapshot y del delta que
/// consume `front`.
#[test]
fn admin_routes_document_their_authorization_responses_and_schemas() {
    let spec = generated_spec_as_json();
    for path in ["/api/admin/metrics", "/api/admin/events"] {
        let responses = &spec["paths"][path]["get"]["responses"];
        for status in ["200", "401", "403", "503"] {
            assert!(
                responses[status].is_object(),
                "{path} debe documentar {status}"
            );
        }
        assert!(
            spec["paths"][path]["get"]["security"].is_array(),
            "{path} debe exigir la cookie de sesión"
        );
    }
    assert!(
        spec["paths"]["/api/admin/events"]["get"]["responses"]["200"]["content"]
            ["text/event-stream"]
            .is_object()
    );
    for schema in [
        "AdminSnapshot",
        "AdminDelta",
        "Kpis",
        "EventEntry",
        "AdminStreamClosed",
    ] {
        assert!(
            spec["components"]["schemas"][schema].is_object(),
            "falta el schema {schema}"
        );
    }
    assert!(spec["components"]["schemas"]["AdminDelta"]["properties"]["seq"].is_object());
}

/// Feature `admin_feed_proxy`: mover el consumidor y el agregador a
/// `events-service` no cambia el contrato público. Las rutas `/api/admin/*` y
/// sus esquemas deben coincidir con el snapshot tomado antes de la
/// extracción (`tests/fixtures/admin_openapi.json`).
#[test]
fn admin_paths_and_schemas_match_the_pre_extraction_snapshot() {
    let spec = generated_spec_as_json();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/admin_openapi.json"))
            .expect("el snapshot debe ser JSON válido");

    let mut paths = serde_json::Map::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        if path.starts_with("/api/admin/") {
            paths.insert(path.clone(), item.clone());
        }
    }
    assert_eq!(serde_json::Value::Object(paths), expected["paths"]);

    let mut schemas = serde_json::Map::new();
    for name in expected["schemas"].as_object().unwrap().keys() {
        schemas.insert(name.clone(), spec["components"]["schemas"][name].clone());
    }
    assert_eq!(serde_json::Value::Object(schemas), expected["schemas"]);
}

/// Feature `report_email_status`: `GET /api/scans` documents the email status
/// of a scan (`email_status` enum and nullable `emailed_at`).
#[test]
fn scan_history_entry_schema_documents_the_report_email_status() {
    let spec = generated_spec_as_json();
    let entry = &spec["components"]["schemas"]["ScanHistoryEntryResponse"];
    assert!(
        entry["properties"]["email_status"].is_object(),
        "ScanHistoryEntryResponse must declare `email_status`: {entry}"
    );
    assert!(
        entry["properties"]["emailed_at"].is_object(),
        "ScanHistoryEntryResponse must declare `emailed_at`: {entry}"
    );
    let status = &spec["components"]["schemas"]["ReportEmailStatus"];
    assert_eq!(
        status["enum"],
        serde_json::json!(["pending", "sent", "failed", "disabled"])
    );
    let required = entry["required"].as_array().cloned().unwrap_or_default();
    assert!(
        !required
            .iter()
            .any(|name| name == "email_status" || name == "emailed_at"),
        "the new fields are additive and optional: {required:?}"
    );
}

/// Task SR-02: the SIEM ingestion route documents its bearer scheme, and no
/// other route references it.
#[test]
fn siem_ingest_route_documents_the_bearer_scheme_only_for_itself() {
    let spec = generated_spec_as_json();
    let scheme = &spec["components"]["securitySchemes"]["siem_bearer"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");

    let post = &spec["paths"]["/api/integrations/siem/alerts"]["post"];
    assert_eq!(post["security"], serde_json::json!([{"siem_bearer": []}]));
    for status in ["202", "400", "401", "413", "422", "429", "503"] {
        assert!(post["responses"][status].is_object(), "missing {status}");
    }
    // D-23: with the feature off the route is unmounted and answers 401 like
    // any unknown path, so no 404 is documented.
    assert!(
        post["responses"]["404"].is_null(),
        "404 must not be documented"
    );

    for (path, item) in spec["paths"].as_object().unwrap() {
        if path == "/api/integrations/siem/alerts" {
            continue;
        }
        assert!(
            !item.to_string().contains("siem_bearer"),
            "{path} must not reference the SIEM bearer scheme"
        );
    }
}

/// Task SR-06: the admin schemas mirror the SIEM fields of events-service.
#[test]
fn admin_schemas_document_the_siem_fields() {
    let spec = generated_spec_as_json();
    let schemas = &spec["components"]["schemas"];
    let required = |name: &str| -> Vec<String> {
        schemas[name]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} has no required list"))
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };

    for (schema, field) in [
        ("Kpis", "siem_alerts"),
        ("Kpis", "siem_alerts_by_severity"),
        ("AdminSnapshot", "siem_enabled"),
        ("AdminSnapshot", "siem_alerts"),
        ("SeriesBucket", "siem_alerts_by_severity"),
    ] {
        assert!(
            schemas[schema]["properties"][field].is_object(),
            "{schema} must declare `{field}`"
        );
        assert!(
            required(schema).contains(&field.to_string()),
            "{schema}.{field} is required"
        );
    }
    // `siem_alert` is nullable and optional, like `critical_finding`.
    assert!(schemas["AdminDelta"]["properties"]["siem_alert"].is_object());

    let mut counts = required("SiemSeverityCounts");
    counts.sort();
    assert_eq!(counts, ["critical", "high", "low", "medium"]);

    let mut alert = required("SiemAlert");
    alert.sort();
    assert_eq!(
        alert,
        [
            "agent",
            "description",
            "event_id",
            "occurred_at",
            "rule_id",
            "rule_level",
            "severity"
        ]
    );
    let props = &schemas["SiemAlert"]["properties"];
    for nullable in ["src_ip", "dest_ip", "signature"] {
        assert!(props[nullable].is_object(), "SiemAlert.{nullable}");
    }
    assert_eq!(props["rule_level"]["maximum"], 15);
    assert_eq!(
        props["severity"]["$ref"],
        "#/components/schemas/SiemSeverity"
    );
    assert_eq!(
        schemas["SiemSeverity"]["enum"],
        serde_json::json!(["low", "medium", "high", "critical"])
    );
    assert_eq!(props["description"]["maxLength"], 256);
    let mut agent = required("SiemAgent");
    agent.sort();
    assert_eq!(agent, ["id", "name"]);
}
