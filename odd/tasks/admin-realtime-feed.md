# admin-realtime-feed (KAP-09)

Feature id: `admin-realtime-feed` | Branch: `feature/admin_realtime_feed` (from `origin/develop` 7fb2e6a)

Master plan: repo `infra`, path `odd/tasks/kinesis-admin-panel.md` (task KAP-09). Producers of the events: this repo (`security-event-publisher`, KAP-06), `nmap-service` (KAP-07), `user-service` (KAP-08). Guard: `odd/tasks/admin-role-guard.md` (KAP-05). Consumer of these routes: KAP-10 (front admin panel).

## Objective

The gateway reads the Kinesis stream `security-events`, aggregates admin metrics in memory, and serves them to admins: `GET /api/admin/metrics` (JSON snapshot) and `GET /api/admin/events` (SSE: snapshot first, then deltas). These are the first routes behind `require_session` + `require_admin`.

## Scope

- Consumer `src/kinesis_consumer.rs`: background task, started only when `SECURITY_EVENTS_STREAM_NAME` is set. `ListShards`, per shard `GetShardIterator(LATEST)` then `GetRecords` polling. Behind a `RecordsSource` port so it is testable without AWS; the AWS adapter reuses the client construction of the publisher.
- Contract validation `src/event_contract.rs`: dependency-free validation of a parsed record against the rules of `broker/contracts/security-event.schema.json` (the schema file is not available at Docker build time, so it is not embedded). A differential test keeps it in step with the real schema.
- Aggregator `src/admin.rs`: pure, clock-injected, bounded memory; `snapshot()` and a `tokio::sync::broadcast` of deltas.
- Routes `src/admin_routes.rs`, OpenAPI schemas, `ROUTES` entries, role re-validation on long SSE connections.
- Guard follow-ups from `odd/tasks/admin-role-guard.md` (latest review advisories): identity-aware user-service stub; 404 from user-service means 403, 401 means misconfigured (still 503).
- Out of scope: front panel (KAP-10), persistence or replay of events, abuse detection, a shared aggregate across instances (every instance reads every event, so each one holds the full view).

## Constraints

- Every instance reads every event (no KCL, no checkpoint): the consumer starts at `LATEST`, so events published while the instance was down are not shown. Accepted: the panel is live observability, not an audit log.
- A malformed or schema-violating record is skipped with a `warn` (no record body in logs) and counted.
- No PII beyond what the schema allows: the log keeps only envelope fields and the payload. `actor_sub` (a pseudonymous OIDC subject) is kept in the raw log; no e-mail, name, token or message body ever exists in an event. The KPI `active_users` is a count, not a list.
- Unit tests: no process-env mutation, no real sleeps beyond a couple of seconds (injected clock for the aggregator, `tokio` paused time for the consumer).
- Docs in neutral Spanish like the rest of `docs/`; code comments in neutral Spanish, identifiers in English; this doc in English.

## Decisions

- D1 Window membership uses the aggregator clock at ingestion time, not `occurred_at`: a producer with a skewed (or forged) clock cannot push events in or out of the 15-minute window. `occurred_at` is still shown in the log.
- D2 Windowed counters (completed, failed, rate-limit hits) use per-second buckets (at most 900 entries for a 15-minute window), so memory is bounded regardless of throughput.
- D3 Duplicates: Kinesis delivers at least once, so the aggregator ignores an `event_id` it saw recently (bounded set of the last 2048 ids).
- D4 Scans in flight: `scan.requested` inserts `requested`, `scan.started` moves it to `running`, `scan.completed|failed|cancelled` remove it. An entry older than 1 hour is dropped (its terminal event was lost) and the set is capped at 1000 entries; the oldest entry is evicted first.
- D5 Active users: distinct `actor_sub` with an `auth.login` inside the window and no later `auth.logout`; capped at 10000 entries (oldest evicted).
- D6 Delta protocol: each delta carries a monotonic `seq`, the new raw-log entry (absent for a malformed record), the fresh KPIs (absolute values, so a lost delta self-heals), an optional in-flight change and an optional critical finding. The snapshot carries the `seq` it reflects; the SSE handler takes snapshot and receiver atomically so no event is missed or duplicated.
- D7 Lag: the broadcast channel holds 256 deltas. A lagging SSE client does not get an error: it gets a fresh `snapshot` event and a new receiver.
- D8 Window expiry changes counters without any event, so the SSE stream also sends a fresh `snapshot` on every re-validation tick (default 60 s).
- D9 SSE re-validation: every `ADMIN_EVENTS_ROLE_RECHECK_SECS` (default 60) the stream calls `current_role` for the session subject. Anything other than a confirmed `admin` (demoted, user gone, user-service down, timeout, misconfigured) sends a generic `closed` event and ends the stream. Fail closed, same policy as `require_admin`.
- D10 `require_admin` mapping: user-service `404` means the user is gone, so `403`; `401` (bad shared secret) stays `503` but logs the distinct kind `misconfigured`; connect, timeout, 5xx and malformed bodies stay `503`. The log carries the error kind, never PII.
- D11 Consumer backoff: 1 s doubling to 30 s on any source error (same constants as the SQS consumer), reset on success. `ExpiredIterator` is not an error: the shard re-acquires `LATEST` immediately (events in the gap are lost, logged as `warn`). Shards are re-listed every 30 s so a resharding adds workers; a closed shard ends its worker.
- D12 Stream not configured: the consumer is not started and the aggregator stays empty; the routes still answer (empty snapshot). One `info` log at startup.

## Metric definitions

| Field | Definition |
|---|---|
| `scans_in_flight` | scans with `scan.requested` or `scan.started` and no terminal event (D4) |
| `completed_last_window` / `failed_last_window` | `scan.completed` / `scan.failed` received in the last 900 s |
| `failure_rate` | `failed / (completed + failed)` in the window, `null` when both are 0 |
| `active_users` | D5 |
| `rate_limit_hits` | `ratelimit.hit` received in the window |
| `critical_findings` | last 50 `finding.critical` (newest first) |
| `recent_events` | last 100 events (newest first), envelope fields plus payload |
| `malformed_records` | records skipped since process start (not windowed) |

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: per stored user policy, decline reviews except per-task authorization/secret work; the guard follow-ups (authorization) are the only review candidate here.

## Checklist

- [x] ARF-01 Feature doc (650cc85).
- [x] ARF-02 Guard follow-ups: identity-aware stub (a), 404 to 403 and `misconfigured` logging (b) (d1f932a).
- [x] ARF-03 Aggregator `src/admin.rs` with clock injection, caps, broadcast, tests first (b558763).
- [x] ARF-04 Contract validation `src/event_contract.rs` plus differential test against the broker schema and examples (79aea8c).
- [x] ARF-05 Consumer `src/kinesis_consumer.rs` (port, fake source tests), AWS adapter, wiring, config `ADMIN_EVENTS_ROLE_RECHECK_SECS` (9a60602).
- [x] ARF-06 Routes `GET /api/admin/metrics` and SSE `GET /api/admin/events`, OpenAPI, `ROUTES`, re-validation (7d07d02).
- [x] ARF-07 LocalStack end-to-end test `tests/admin_feed_localstack.rs` (e9683c8).
- [x] ARF-08 Docs (`docs/architecture.md`, `docs/security-scope.md`, README env table) and this doc closed (docs commit on top of e9683c8).

## Routes and status codes

| Route | 200 | 401 | 403 | 503 |
|---|---|---|---|---|
| `GET /api/admin/metrics` | JSON `AdminSnapshot` | no valid session | not admin, demoted, or user gone | role not verifiable |
| `GET /api/admin/events` | `text/event-stream`: `snapshot`, `delta`, `closed`, `: ping` every 15 s | same | same | same |

## Evidence

- RED ARF-02: `tests/admin_role_guard.rs` did not compile (`no method named kind found for enum UsuariosClientError`); the new tests then drove the `404 -> 403` mapping.
- GREEN ARF-02: `admin_role_guard` 17 passed (13 before). `require_admin` logic moved to `auth::verify_admin`, shared with the SSE re-validation.
- RED ARF-03: `cargo test --lib admin` failed to compile (30 errors, `AdminAggregator`, `ManualClock` and constants missing). GREEN: 20 passed.
- RED ARF-04: `tests/admin_event_contract.rs` failed to compile (`event_contract` module missing). GREEN: 3 passed; the differential test compared the consumer verdict with the real schema on 411 mutations of the 11 broker examples with zero divergences.
- RED ARF-05: `cargo test --lib kinesis_consumer` and `config` (role recheck) failed to compile (types missing). GREEN: 10 consumer tests (LATEST start, next-iterator follow, 1 s poll, malformed skip and count, expired iterator re-acquires LATEST, exponential backoff 1/2/4/8 then reset, backoff cap, closed shard, new shard on refresh, list failure backoff, prompt shutdown), 2 config tests.
- RED ARF-06: `tests/admin_routes.rs` failed to compile (`admin_routes` module missing). GREEN: 10 route tests (401, 403 non-admin, 403 demoted, 503 unverifiable, JSON snapshot, SSE snapshot then delta, periodic snapshot on re-validation, close after revocation, close when unverifiable, close when the user disappears), 1 lag unit test (`a_lagging_client_gets_a_fresh_snapshot_instead_of_an_error`; written together with the implementation, no separate RED), OpenAPI test.
- ARF-07: `admin_feed_localstack` passed on its first run (no separate RED: it composes units already proven RED/GREEN above). It publishes through the KAP-06 publisher plus raw nmap-style records and one garbage record, and reads `/api/admin/metrics` from the real router.
- Final: `make verify` exit 0 (fmt, clippy `-D warnings`, unit and integration tests, ignored LocalStack suites, `cargo doc`; the one rustdoc warning in `src/wiring.rs` predates this feature). `cargo test --lib` 143 passed on three consecutive runs. `cargo test --test admin_feed_localstack -- --ignored` 1 passed. No native review run (user policy: decline except authorization/secret tasks; the guard follow-ups were not submitted).

## Known limitations

- Events published while an instance is down, or in the gap after an expired iterator, are not shown (`LATEST` start, no checkpoint).
- No persistence: a restart empties the panel.
- A scan whose terminal event is lost stays "in flight" for up to 1 hour.
- `malformed_records` is not windowed (it counts since process start).
- The re-validation tick is per connection; a revoked admin can keep an open stream for up to `ADMIN_EVENTS_ROLE_RECHECK_SECS` (60 s) plus the 2 s role-check timeout.

## Next step

KAP-10: `front` admin panel (`features/admin/`) consuming `GET /api/admin/metrics` and the SSE `GET /api/admin/events` (events `snapshot`, `delta`, `closed`).
