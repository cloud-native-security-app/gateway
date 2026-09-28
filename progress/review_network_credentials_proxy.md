# Review — feature 14 (network_credentials_proxy)

**Veredicto:** APPROVED

## Verificación realizada

- Releídos `docs/architecture.md`, `docs/conventions.md`,
  `docs/security-scope.md`, `CHECKPOINTS.md`, `feature_list.json` (id 14,
  `acceptance` completo) y `progress/current.md`.
- Confirmado el contrato real de `ms-usuarios` por lectura directa (no
  asumido): `../user-service/src/domain.rs` líneas 151-170
  (`NetworkCredential`, sin `ssh_credentials_ref`) y
  `../user-service/src/api.rs` líneas 401-483 (`upsert_network_credential`/
  `list_network_credentials`/`delete_network_credential`, 404 nunca 403 en
  delete de entrada ajena/inexistente).
- Leídos íntegros `src/usuarios_client.rs`, `src/api.rs`,
  `tests/network_credentials_proxy.rs`, `docs/security-scope.md` (nueva
  subsección).
- Ejecutado de forma independiente: `cargo fmt --check` (OK),
  `cargo clippy --all-targets -- -D warnings` (OK, 0 warnings),
  `./init.sh` completo con Docker disponible (incluye
  `cargo test -- --ignored` contra RabbitMQ real vía `testcontainers`) —
  **verde de punta a punta**. `cargo test --test network_credentials_proxy`
  por separado: 7/7 tests pasan.
- Verificado que `git status`/`git diff` en `user-service` y `front` no
  muestran cambios (nada tocado fuera de `gateway/`); el `docker-compose.yml`
  raíz y `deploy/aws/*` que aparecen "recientes" por mtime son de una tarea
  no relacionada (scripts de despliegue AWS) y no mencionan
  `network-credentials`.

## Puntos verificados contra el `acceptance`

1. **3 métodos nuevos en `UsuariosClient`**, mismo patrón que
   `get_profile`/`upsert_profile` (`send_and_decode`, mismos headers
   `FORWARDED_USER_HEADER_NAME`/`GATEWAY_SECRET_HEADER_NAME`) —
   `src/usuarios_client.rs:553-640`. Correcto.
2. **`NetworkCredential`** (`src/usuarios_client.rs:198-213`) espeja
   exactamente `{id, user_id, target_pattern, network_user, has_sudo,
   created_at, updated_at}` — **sin** `ssh_credentials_ref`, confirmado
   contra `user-service/src/domain.rs:151-170`. `CreateNetworkCredentialRequest`
   (línea 227-237) sí lo incluye, con `Debug` redactado a mano
   (línea 239-247), mismo criterio que `ScanTargetCredentials`.
3. **3 rutas en `protected_router`** (`src/api.rs:405-412`), en `ROUTES` con
   `protected: true` (líneas 1071-1085), documentadas con
   `#[utoipa::path]` y registradas en `ApiDoc` (líneas 1211-1213,
   1221-1222) y tag `network-credentials` (línea 1230). El test anti-drift
   `tests/openapi_docs.rs::every_route_in_the_canonical_table_is_documented_in_the_generated_openapi_spec`
   cubre esto y pasa.
4. **GET/POST nunca exponen `ssh_credentials_ref`**: el tipo `NetworkCredential`
   no declara el campo, verificado con test unitario
   `network_credential_never_serializes_an_ssh_credentials_ref_field` y con
   el test de integración que hace que el stub incluya el campo a propósito
   y confirma su ausencia en la respuesta real del Gateway
   (`tests/network_credentials_proxy.rs:117-134`, `356-421`).
5. **DELETE reenvía 404 real, no 502 genérico**: variante dedicada
   `UsuariosClientError::NetworkCredentialNotFound`
   (`src/usuarios_client.rs:301-309`), distinguida explícitamente en
   `delete_network_credential` (líneas 610-640, antes de caer al
   `UnexpectedResponse` genérico), mapeada a `StatusCode::NOT_FOUND` en
   `impl IntoResponse for UsuariosClientError` (`src/api.rs:1417-1421`).
   Probado en
   `delete_network_credential_of_an_unknown_or_foreign_entry_returns_not_found`.
6. **Mismo manejo de errores que profile** para red/5xx ->
   502/504 sin exponer URL interna: confirmado en
   `network_credentials_with_rejected_service_credential_returns_a_generic_gateway_error`
   y `network_credentials_when_ms_usuarios_is_unreachable_returns_a_gateway_error_without_leaking_its_url`.
7. **Doc OpenAPI** completa para los 3 endpoints, mismo formato que el resto.
8. **`docs/security-scope.md`** actualizado con la subsección "Credenciales
   de red (feature `network_credentials_proxy`)" — reafirma correctamente
   que `ssh_credentials_ref` solo viaja en el body del `POST` hacia
   `ms-usuarios`, nunca en una respuesta de este Gateway.
9. **7 tests de integración nuevos**, mismo patrón que
   `tests/usuarios_profile_proxy.rs`: camino feliz de los 3 endpoints, sin
   sesión (401), credencial de servicio rechazada (502), `ms-usuarios`
   caído (502/504 sin leak de URL), delete ajeno/inexistente (404). Todos
   verdes.
10. `cargo test` e `./init.sh` verdes — confirmado independientemente.

## Otras verificaciones de `docs/security-scope.md`

- No hay `println!`/`dbg!`/`unwrap()`/`panic!()` fuera de tests en el código
  nuevo de `src/usuarios_client.rs`/`src/api.rs`.
- `src/` solo contiene los módulos previstos en `docs/architecture.md`.
- Ninguna ruta protegida queda fuera del middleware de sesión: las 3 rutas
  nuevas están dentro de `protected_router`, bajo la misma capa
  `require_session` que el resto.

## Nota fuera del alcance de esta feature (no bloquea el veredicto)

El working tree tiene cambios sin commitear de las features 12
(`post_login_redirect`) y 13 (`cors_for_front`), ya `done` y ya aprobadas en
sesiones anteriores (ver `progress/history.md`), más `progress/review_cors_for_front.md`
y `progress/review_post_login_redirect.md` sin trackear. Nada de esto lo tocó
el implementer de la feature 14; se deja constancia por higiene de C5, pero
no es un hallazgo de esta feature.

## Cambios requeridos

Ninguno.
