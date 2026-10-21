# scan-report (gateway part)

Feature id: `scan-report` | Branch: `feature/scan_report` | Option A (user decision 2026-10-20)

Master plan: repo `front`, `odd/tasks/scan-report.md` (SRP-02 gateway). User-service contract: `user-service/odd/tasks/scan-report.md`.

## Objective

Persist the scan result / failure reason / cancelled state in `ms-usuarios` from the outcome relay, and expose them to the front.

## Scope

- `usuarios_client`: `update_scan_outcome` (result with `COMPLETADO`, `failure_reason` with `FALLIDO`/`CANCELADO`), `ScanStatus::Cancelado`, `ScanHistoryEntry.failure_reason`, `get_scan_report` (200 / 404 `ScanReportNotFound` / 409 `ScanReportNotReady` / other).
- `ScanOutcomeRelay` (now public, `ScanOutcomeRelay::new`): `completed` -> `COMPLETADO` + result; `failed` -> `FALLIDO` + reason, or `CANCELADO` + reason if cancellation was requested through this gateway.
- `ScanOwnershipRegistry::mark_cancel_requested` / `is_cancel_requested`, set by `cancel_scan` after the Broker accepts the cancellation.
- `GET /api/scans` entries gain `failure_reason` (always present, nullable); status may be `CANCELADO`. Cancel returns `409` also for `CANCELADO`.
- New `GET /api/scans/{scan_id}/report` (session required; 200 `ScanResult`, 404, 409 text `el reporte del escaneo aún no está disponible`, 502/504); OpenAPI + `ROUTES` updated.
- SSE shape unchanged.

## Tasks

- [x] T1 Tests first (usuarios_client, relay, history/cancel, report API), RED recorded.
- [x] T2 usuarios_client changes.
- [x] T3 Relay + cancel marker + reason sanitization.
- [x] T4 API: history fields, report endpoint, OpenAPI.
- [x] T5 README, docs, this document.
- [x] T6 `make verify`.

TDD: enabled, runner `cargo test` / `cargo test -- --ignored`. Route: delegated direct, single writer.

## Decisions

- Cancel marker is in-memory (in `ScanOwnershipRegistry`): lost on a gateway restart; the scan then shows `FALLIDO` with nmap's cancellation reason (accepted). nmap's reason text is never matched.
- Marker is set only after the Broker accepted the cancellation.
- `ScanOutcomeRelay` made public so the real relay is tested (the duplicate `TestRelayHandler` was removed).
- Reason sanitized for user-service limits (blank -> "motivo no informado", cap 500 chars). A `413` on the result degrades to `COMPLETADO` without result (report then answers 409) instead of leaving the scan non-terminal.
- Error bodies of the gateway are plain text (existing convention), so the report `409` body is the Spanish text, not JSON.
- SSE not changed (the front guard ignores unknown fields, but a `cancelled` flag was not needed).
- Known limitation: `scanId` mapping is in-memory, so after a gateway restart `/report` for older scans returns 404 and history entries have no `scanId`.

## Evidence

- RED: `cargo test --no-run` failed to compile: missing `update_scan_outcome`, `get_scan_report`, `ScanStatus::Cancelado`, `ScanHistoryEntry::failure_reason`, `UsuariosClientError::ScanReport*`, `mark_cancel_requested`/`is_cancel_requested`, private `ScanOutcomeRelay`.
- GREEN: `make verify` exit 0 (fmt, clippy -D warnings, unit+integration tests, ignored LocalStack suites, cargo doc); 167 test results passed across both test runs, 0 failed.
