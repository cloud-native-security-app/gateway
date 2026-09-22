# Fix puntual: nombres de header hacia `ms-usuarios` en `usuarios_client`

> No es una feature de `feature_list.json` (la feature 5, `usuarios_profile_proxy`,
> sigue `done` y no se tocó su estado). Corrección mecánica de nombres de
> header tras confirmar el contrato real de `ms-usuarios` leyendo (solo
> lectura, otro repo) `user-service/src/api.rs` líneas ~65-69.

## Qué cambió

- `src/usuarios_client.rs`:
  - `IDENTITY_HEADER_NAME = "X-Gateway-Identity"` →
    `FORWARDED_USER_HEADER_NAME = "X-Forwarded-User"` (nombre de constante
    renombrado para quedar coherente con el nombre real del header, que ya
    no menciona "Identity"; mismo patrón de nombre que
    `user-service/src/api.rs::FORWARDED_USER_HEADER`).
  - `SERVICE_SECRET_HEADER_NAME = "X-Gateway-Service-Secret"` →
    `GATEWAY_SECRET_HEADER_NAME = "X-Gateway-Secret"` (mismo criterio, mismo
    patrón de nombre que `user-service/src/api.rs::GATEWAY_SECRET_HEADER`).
  - Doc-comments del módulo (`//!` al inicio) y de cada constante
    actualizados: ya no dicen "decisión de diseño de este repo, no un dato
    tomado de `user-service/docs`" (eso ya no es cierto), sino que
    referencian explícitamente `user-service/src/api.rs` como fuente
    confirmada.
  - Ningún otro comportamiento tocado: mismas rutas (`GET`/`PUT /users/me`),
    mismo shape opaco de `UserProfile` (sigue siendo suposición documentada,
    no se confirmó contra `user-service/src/domain.rs` en este fix porque no
    era obligatorio y el alcance pedido era puntual), misma lógica de
    errores (`UsuariosClientError` sin cambios), misma estructura del
    módulo.
- `tests/usuarios_client.rs`: imports y usos de
  `IDENTITY_HEADER_NAME`/`SERVICE_SECRET_HEADER_NAME` actualizados a los
  nuevos nombres de constante. El stub HTTP de `ms-usuarios` ya usaba las
  constantes (no un literal de header separado), así que no había
  duplicación que corregir.
- `tests/usuarios_profile_proxy.rs`: revisado, no referencia estas
  constantes ni los nombres de header directamente (ejercita el proxy vía
  `app_router` end-to-end), así que no requirió cambios.
- `src/api.rs`, `tests/oidc_login.rs`, `tests/session_middleware_and_me.rs`:
  revisados, solo usan el tipo `UsuariosClient`, no las constantes de
  header. Sin cambios.

## Grep de confirmación (sin referencias a los nombres viejos)

```
$ grep -rn "X-Gateway-Identity\|X-Gateway-Service-Secret\|IDENTITY_HEADER_NAME\|SERVICE_SECRET_HEADER_NAME" --include="*.rs" .
(sin resultados)
```

## Verificación

- `cargo build 2>&1` → compila sin errores.
- `cargo clippy --all-targets -- -D warnings 2>&1` → sin warnings.
- `cargo fmt --check` → sin diferencias.
- `cargo test 2>&1` → 19 unit + 8 (`oidc_login`) + 5
  (`session_middleware_and_me`) + 6 (`usuarios_client`) + 3
  (`usuarios_profile_proxy`) = 41 tests, todos `ok`. Ninguna feature 1-5 se
  rompió.
- `./init.sh` → todas las secciones en verde (`fmt`, `clippy`, tests
  unitarios, tests con Docker marcados `#[ignore]` — no hay ninguno
  aplicable aquí —, `cargo doc`). Termina con "Entorno listo."

## Archivos tocados

- `src/usuarios_client.rs`
- `tests/usuarios_client.rs`
- `progress/impl_fix_usuarios_client_headers.md` (este informe)
