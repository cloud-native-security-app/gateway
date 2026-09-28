# Review — feature 15

**Veredicto:** APPROVED

## Checkpoints

- C1: [x] — Existen `AGENTS.md`, `init.sh`, `feature_list.json`, `progress/current.md`, los 4 docs (`docs/architecture.md`, `docs/conventions.md`, `docs/verification.md`, `docs/security-scope.md`) y `CHECKPOINTS.md`. `./init.sh` corrido de forma independiente por este reviewer termina con exit code 0 (confirmado explícitamente con `echo $?`).
- C2: [x] — Solo la feature 15 está `in_progress` en `feature_list.json` (verificado con `jq`/script: `in_progress count: 1`). `progress/current.md` describe únicamente la sesión activa de la feature 15, sin basura de sesiones anteriores. Las features `done` (1–14) no fueron tocadas por este diff.
- C3: [x] — El diff real (`git diff -- src/auth.rs`) toca únicamente `removal_cookie()` (líneas ~436-443) agregando `.http_only(true).secure(true).same_site(SameSite::Strict)` antes de `.path("/")`, exactamente lo que pide el `acceptance` de la feature 15 y coherente con `docs/architecture.md`/`docs/security-scope.md` (la sesión propia de Gateway es `HttpOnly`+`Secure`+`SameSite=Strict`, y la cookie de borrado debe llevar los mismos atributos o el navegador la ignora). No se creó ningún módulo nuevo, no se tocó `Cargo.toml`, no hay `println!`/`dbg!` nuevos, no hay `unwrap()`/`panic!()` nuevos fuera de tests, `cargo doc --no-deps` genera sin warnings (confirmado en la corrida de `./init.sh`). No se inventó ningún shape de API pendiente — el fix es puramente de atributos de cookie.
- C4: [x] — El test `removal_cookie_matches_session_cookie_name_and_path` (src/auth.rs ~L582-604) se extendió correctamente: ahora compara `removal.secure()`, `removal.http_only()` y `removal.same_site()` contra los mismos atributos de una `session_cookie()` real construida en el propio test, además de nombre y path — cubre exactamente la regresión que causó el bug. `cargo test` y `cargo test -- --ignored` (con Docker) pasan en verde según la corrida de `./init.sh` de este reviewer. `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — No hay archivos sueltos sospechosos (`*.tmp`) introducidos por este fix. `progress/current.md` refleja el estado correcto de la feature 15 en curso, a la espera de este veredicto. (Los demás archivos con diff sin commitear en el árbol de trabajo — `src/api.rs`, `src/config.rs`, `src/usuarios_client.rs`, `src/wiring.rs`, tests de otras features, `docs/security-scope.md`, `README.md`, `feature_list.json`, `progress/history.md` — corresponden a features anteriores ya aprobadas (13 `cors_for_front`, 14 `network_credentials_proxy`, ambas `done` con su propio `progress/review_<feature>.md` ya presente) y están fuera del alcance de esta revisión, que cubre exclusivamente lo que `progress/current.md` reporta para la feature 15: `src/auth.rs`.)

## Verificación de seguridad (docs/security-scope.md)

- No se filtra el token de Google, la sesión firmada, la credencial de `ms-usuarios` ni la credencial AMQPS: el diff no toca logs, mensajes de error, ni respuestas HTTP — solo atributos de protocolo de cookie (`HttpOnly`/`Secure`/`SameSite`), que no son secretos.
- Ninguna ruta protegida quedó sin el middleware de sesión (RF-10): la tabla `ROUTES`/`protected_router` en `src/api.rs` no fue modificada por este diff. `POST /auth/logout` permanece correctamente fuera del middleware (`protected: false`, `src/api.rs` línea ~1089) — es el comportamiento ya documentado y esperado (un logout debe poder ejecutarse incluso con sesión inválida/expirada).
- `CookieJar::remove()` (usado en el handler `logout`, `src/api.rs` línea ~1346) no fue tocado, tal como reporta `progress/current.md`; sigue fijando `Max-Age=0`/`Expires` en el pasado, ahora combinado correctamente con `Secure` gracias al fix de `removal_cookie()`.

## Verificación de `./init.sh`

Corrido de forma independiente por este reviewer (no reutilizando la corrida del implementer): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo test -- --ignored` (con Docker real disponible) y `cargo doc --no-deps` — todos en verde, exit code final `0`.

## Cambios requeridos (si aplica)

Ninguno.
