# Review — fix puntual: nombres de header hacia `ms-usuarios`

> No es una feature de `feature_list.json`; corrección post-hoc de un detalle
> de la feature 5 (`usuarios_profile_proxy`, sigue `done`). Ver
> `progress/impl_fix_usuarios_client_headers.md`.

**Veredicto:** APPROVED

## Evidencia

### 1. Grep de confirmación (nombres viejos)

```
$ grep -rn "X-Gateway-Identity\|X-Gateway-Service-Secret" . --include="*.md" --include="*.rs" --include="*.toml" (excluyendo target/)
progress/history.md:224-226        (log histórico, sesión de la feature 5, ya commiteado en a2724de)
progress/impl_usuarios_profile_proxy.md:37,44,144  (informe histórico del implementer de la feature 5)
progress/review_usuarios_profile_proxy.md:99-100   (mi propio veredicto histórico de la feature 5)
progress/current.md:18-19          (explica el fix explícitamente: "distintos de X-Gateway-Identity/... que la feature 5 asumió")
progress/impl_fix_usuarios_client_headers.md:11,16,45  (el propio informe del fix, citando qué se reemplazó)
```

Cero resultados en `src/`, `tests/`, `docs/`, `README.md` (verificado con
`grep -rln "X-Gateway-Identity\|X-Gateway-Service-Secret" docs/ src/ tests/ README.md` → sin salida).
Las únicas apariciones de los nombres viejos están en registros de progreso
(`progress/*.md`) que documentan el histórico de sesiones anteriores —
correcto que sigan mencionando el nombre viejo al narrar qué se corrigió;
reescribirlos falsearía el historial. Código y documentación viva
(`docs/architecture.md`, `docs/security-scope.md`, `docs/conventions.md`,
`src/`, `tests/`) están limpios.

### 2. Grep de confirmación (nombres nuevos en uso)

```
$ grep -n "FORWARDED_USER_HEADER_NAME\|GATEWAY_SECRET_HEADER_NAME" src/usuarios_client.rs tests/usuarios_client.rs
src/usuarios_client.rs:44:  pub const FORWARDED_USER_HEADER_NAME: &str = "X-Forwarded-User";
src/usuarios_client.rs:51:  pub const GATEWAY_SECRET_HEADER_NAME: &str = "X-Gateway-Secret";
src/usuarios_client.rs:143,148,166,171: uso en las llamadas GET/PUT /users/me
tests/usuarios_client.rs:20,47,62: import y uso en el stub HTTP
```

`tests/usuarios_profile_proxy.rs` no referencia los nombres de header
directamente (ejercita el proxy end-to-end vía `app_router`), confirmado —
correcto según lo reportado por el implementer, no requería cambios.

### 3. Diff mínimo y mecánico (`git diff` sobre working tree)

- `src/usuarios_client.rs`: solo renombre de las dos constantes
  (`IDENTITY_HEADER_NAME` → `FORWARDED_USER_HEADER_NAME`,
  `SERVICE_SECRET_HEADER_NAME` → `GATEWAY_SECRET_HEADER_NAME`), sus valores
  literales, y actualización de los doc-comments (`//!` del módulo y `///`
  de cada constante/uso) para reflejar que el contrato ya está confirmado
  contra `user-service/src/api.rs`. Sin cambios de rutas (`/users/me`
  intacta), sin cambios de shape de `UserProfile`, sin cambios de
  `UsuariosClientError`, sin lógica nueva.
- `tests/usuarios_client.rs`: solo el import y los dos usos de las
  constantes renombradas. Sin nuevos tests, sin tests eliminados, sin
  cambio de aserciones más allá del nombre de la constante.
- Ningún archivo fuera de `src/usuarios_client.rs` y `tests/usuarios_client.rs`
  fue tocado en cuanto a código (`progress/current.md` es documentación de
  progreso, fuera del alcance de `src/`/`tests/`).
- No hay ninguna línea que loggee `shared_secret`/`expose_secret()` — las
  dos únicas apariciones de `expose_secret()` (líneas 146 y 169) siguen
  siendo exclusivamente para setear el header saliente hacia `ms-usuarios`,
  igual que antes del fix. Ningún `tracing::`/`println!`/`eprintln!` toca
  el secreto ni el header de identidad.

### 4. Comandos de verificación

- `cargo build 2>&1` → `Finished` sin errores ni warnings.
- `cargo clippy --all-targets -- -D warnings 2>&1` (re-ejecutado forzando
  recompilación de `src/usuarios_client.rs` con `touch` para confirmar que
  no era una corrida cacheada) → `Finished` sin warnings.
- `cargo fmt --check` → sin diferencias.
- `cargo test 2>&1` → 19 unit + 8 (`oidc_login`) + 5
  (`session_middleware_and_me`) + 6 (`usuarios_client`) + 3
  (`usuarios_profile_proxy`) = 41 tests, todos `ok`. Ninguna feature 1-5 se
  rompió.
- `./init.sh` → `fmt`, `clippy`, tests unitarios, tests de integración con
  Docker (`#[ignore]`, ninguno aplicable a este fix), y `cargo doc` en
  verde. Termina con "Entorno listo. Puedes empezar a trabajar."

## Checkpoints

No aplica — este fix no corresponde a ningún checkpoint nuevo de
`CHECKPOINTS.md`; es una corrección puntual sobre la feature 5
(`usuarios_profile_proxy`), que ya estaba `done` y cuyos checkpoints
asociados siguen cumpliéndose sin cambios (la sesión propia y la ruta
`/users/me` protegida no fueron tocadas por este fix).

## Cambios requeridos

Ninguno.
