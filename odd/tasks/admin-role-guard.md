# admin-role-guard (KAP-05)

Feature id: `admin-role-guard` | Branch: `feature/admin_role_guard` (from `origin/develop` b292ed3)

Master plan: repo `infra`, path `odd/tasks/kinesis-admin-panel.md` (task KAP-05). Producer of the role: `user-service/odd/tasks/user-role.md` (KAP-04). Consumers: KAP-09 (`/api/admin/*`) and KAP-10 (front).

## Objective

The gateway learns the user's role from `ms-usuarios` at login, carries it in its own session JWT as a `role` claim, exposes it in `GET /api/me`, and offers a reusable `require_admin` guard that answers `403` to non-admins.

## Scope

- `usuarios_client`: parse `role` from the profile returned by `PUT /users/me` into `domain::Role` (`user`/`admin`).
- Login (`/auth/callback`): put that role in `Session` and in the signed JWT (`role`, lowercase).
- `auth::require_admin`: middleware layer that runs after `require_session` and requires `role == admin`.
- `GET /api/me` returns `role`; OpenAPI schema updated.
- No admin route is added here (KAP-09). The guard is proven on a test-only router.
- Out of scope: any way to change a role (lives in `user-service`), server-side session revocation.

## Constraints

- Security-sensitive (authorization): the role is authoritative only from `ms-usuarios` at login. No header, query, cookie value or body field set by the client can set it; only a token signed with the gateway key is trusted.
- Fail closed to least privilege: every missing or unrecognized role resolves to `user`, never to `admin`.
- Error bodies follow the existing plain-text convention and never leak the role or any claim.
- Unit tests do not mutate the process environment and have no wall-clock waits.
- Docs and code comments in neutral Spanish like the rest of this repo; identifiers in English; this doc in English like the other `odd/tasks` docs.

## Decisions

- D1 Claim: `role`, lowercase string `"user"` / `"admin"` (same wire format as `user-service`). `domain::Role` implements `Default = User`.
- D2 Missing `role` in the `ms-usuarios` profile (older `user-service`): `User`, silently (backward compatible).
- D3 Unknown `role` value in the profile (contract drift): `User` plus a `tracing::warn!` that carries no personal data and not the received value. Never `admin`.
- D4 JWT without `role` claim (issued before this change): decodes as `User` (`#[serde(default)]`), never admin. A token whose `role` is a value the gateway does not know fails to decode, so the session is rejected (`401`).
- D5 `require_admin` is a middleware layer (same style as `require_session`) and must be applied inside it. If it ever runs without a `Session` extension (misconfigured router) it answers `401`, never lets the request through.
- D6 `403` body is the generic text `acceso denegado`; `401` stays `sesión inválida o ausente`.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: authorization, so a review is allowed.

## Checklist

- [x] ARG-01 Feature doc.
- [x] ARG-02 `domain::Role`, `usuarios_client::role_from_profile` (missing and unknown handling), tests first (a9f8f7d).
- [x] ARG-03 `Session.role`, `role` claim, login wiring, `GET /api/me` `role`, OpenAPI (19b9526).
- [x] ARG-04 `auth::require_admin`, `AuthError::AdminRequired` (`403`), forged-token and non-admin tests (49e50fb).
- [x] ARG-05 `docs/security-scope.md`, `docs/architecture.md`, this doc closed (docs commit on top of 49e50fb).

## Known limitations

- A role change in `user-service` (grant or revoke) takes effect at the user's next login: the role lives in the session JWT until it expires (`session_ttl_secs`). There is no server-side revocation (already a documented limit of this gateway).
- The gateway trusts the `role` field of the `PUT /users/me` response; it relies on `user-service` never accepting a role from a request body (KAP-04).

## Evidence

- RED ARG-02: `cargo test --lib --no-run` failed: `cannot find type Role in this scope` (domain and `role_from_profile` tests).
- GREEN ARG-02: `cargo test --lib` 88 passed; clippy `-D warnings` clean. `Session.role` added with mechanical updates of every `Session` literal.
- RED ARG-03: `cargo test --lib` 2 failed (`session_token_carries_the_role_claim_in_lowercase`, `token_with_unknown_role_claim_is_rejected`); `cargo test --test oidc_login` 5 failed (admin/user/missing/unknown role, client-supplied role).
- GREEN ARG-03: `cargo test --lib` 91 passed; `oidc_login` 17, `session_middleware_and_me` 9, `openapi_docs` 3 passed.
- RED ARG-04: `tests/admin_role_guard.rs` failed to compile: `unresolved import gateway::auth::require_admin`.
- GREEN ARG-04: `admin_role_guard` 8 passed (admin 200; validly signed user 403 with body `acceso denegado`; no cookie 401; wrong-key forged admin 401; payload edited to admin 401; `alg: none` 401; header/query/cookie role hints 403; no session layer 401).
- Final: `make verify` exit 0 (fmt, clippy `-D warnings`, unit and integration tests, ignored LocalStack suites, `cargo doc`); `cargo test --lib` 91 passed on three consecutive runs.
- Review: no pre-commit hook is installed in this checkout (only samples). Native review (high risk, 20 files, 829 lines) granted by the user 2026-11-10: four lenses (risk, resilience, readability, reliability), **approved** and acknowledged (lineage `review-d8600dec84d5befb`). Non-blocking advisory findings, kept as follow-ups:
  - R1-001 (risk, SUGGESTION, `src/api.rs:1536`): the role is snapshotted into the session JWT with no server-side revocation, so a demoted admin keeps admin authority until the session expires. Not exploitable today (no `/api/admin/*` route). **Must be resolved in KAP-09** before admin routes are mounted: re-check the role against `user-service` inside `require_admin`, or use a short TTL for admin sessions.
  - R2-dup-callback-role-test (readability, WARNING, `tests/oidc_login.rs:1169-1225`) and R3-001 (reliability): `callback_ignores_a_role_supplied_by_the_client_request` duplicates the `login_and_read_role_claim` helper and drops its `302 FOUND` assertion.
  - R2-duplicated-signing-key-literal (readability): the session signing key literal is repeated in test decoders and `src/auth.rs` test helpers; use one named constant.
  - R2-role-parse-parallel-decoder (readability, `src/domain.rs:24-34`): `Role::parse` duplicates the serde lowercase mapping; derive it from serde or add a test that both paths agree on every variant.

## Next step

KAP-06 (event producers) and KAP-09 (`/api/admin/*` routes behind `require_session` + `require_admin`); KAP-09 must first resolve review finding R1-001 (role revocation).
