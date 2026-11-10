# security-event-publisher (KAP-06)

Feature id: `security-event-publisher` | Branch: `feature/security_event_publisher` (from `origin/develop` 5d1a08f)

Master plan: repo `infra`, path `odd/tasks/kinesis-admin-panel.md` (task KAP-06). Contract: `broker/contracts/security-event.schema.json` and `broker/contracts/examples/security-event/`. Stream: `security-events` (KAP-01 cloud, KAP-02 LocalStack). Consumer of these events: KAP-09.

## Objective

The gateway publishes immutable security events to the Kinesis stream `security-events` through a `SecurityEventPublisher` port, without ever affecting the business operation that caused them.

## Scope

- Port `SecurityEventPublisher` (`Arc<dyn ...>` in `AppState`), domain envelope `SecurityEvent` with one typed constructor per gateway-owned event, serialized exactly as the broker schema.
- Adapters: Kinesis (`aws-sdk-kinesis`, honors `AWS_ENDPOINT_URL`), in-memory recorder (tests), no-op (stream not configured).
- Config `SECURITY_EVENTS_STREAM_NAME` (optional). Unset or empty means the no-op adapter plus one startup info log.
- Emission points: `scan.requested`, `scan.cancelled`, `auth.login`, `auth.logout`, `ratelimit.hit`, `message.deadlettered`.
- Contract parity tests against the sibling `../broker` checkout and a LocalStack round trip.
- Out of scope: consuming the stream (KAP-09), events owned by nmap-service (KAP-07) and user-service (KAP-08), retries or a local outbox.

## Constraints

- A Kinesis failure is logged (event type only) and never fails or changes the HTTP response of the operation.
- Events never carry credentials, tokens, emails, raw scan output, or message bodies; payload fields are exactly the schema's.
- Partition key: `scan_id`, else `actor_sub`, else `event_id`.
- Every emitted event validates against the broker schema; the examples deserialize into `SecurityEvent`. If `../broker` is absent the parity tests print a notice and pass (same pattern as broker `tests/topology_parity.rs`).
- Unit tests do not mutate the process environment and have no wall-clock waits.
- Docs and code comments in neutral Spanish like the rest of this repo; identifiers in English; this doc in English like the other `odd/tasks` docs.

## Decisions

- D1 Failure isolation: publish in a detached `tokio::spawn` task bounded by a 5 s timeout, instead of awaiting inline. The request path pays no Kinesis latency and no error path. The price is that an event can be lost on a crash or shutdown before the task runs (acceptable: events are observability facts, the business state is authoritative).
- D2 `auth.logout` is emitted only when the request carries a valid session cookie (the schema requires `actor_sub`). Logout stays outside the session middleware (D-09), so an invalid or absent cookie still gets `204` and no event.
- D3 `ratelimit.hit` is emitted only for `POST /api/scans` (the only rate-limited route), with the route without query string, the configured max requests as `limit`, and the window in seconds.
- D4 `message.deadlettered` is emitted by the SQS consumer after the malformed message was copied to the DLQ: `queue` is the source queue name taken from its URL, `reason_code` is `malformed_message`. The body is never included.
- D5 Constructors validate the schema's field constraints (lengths, patterns, IP) and return an error instead of an invalid event; an invalid event is logged (type and field name only) and dropped.
- D6 `scan.cancelled` carries an empty payload (the cancel handler does not hold the target; the schema makes it optional).
- D7 No `schema_version` (contract decision D-14).

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: decline (stored user policy; this task touches no permission or secret).

## Checklist

- [x] SEP-01 Feature doc (d9171f2).
- [x] SEP-02 `SecurityEvent` envelope, port, recorder and no-op adapters, `emit`, schema parity tests (579ed7a).
- [x] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, wiring, LocalStack tests; also the `message.deadlettered` emission in the SQS consumer, since it needed the same wiring (b360828).
- [x] SEP-04 Emission points `scan.requested`, `scan.cancelled`, `auth.login`, `auth.logout`, `ratelimit.hit`, each with a failing-publisher test (26422ca).
- [x] SEP-05 `docs/architecture.md`, `docs/security-scope.md`, README env table, this doc closed (docs commit on top of 26422ca).

## Emission points

| Event | Where | Condition |
|---|---|---|
| `scan.requested` | `src/api.rs` `submit_scan` | after `publish_scan_request` succeeded |
| `scan.cancelled` | `src/api.rs` `cancel_scan` | after `publish_scan_cancellation` succeeded |
| `auth.login` | `src/api.rs` `callback` | after the session token was issued |
| `auth.logout` | `src/api.rs` `logout` | only with a valid session cookie |
| `ratelimit.hit` | `src/api.rs` `rate_limit_scan_submission` | each rejected request, before the 429 |
| `message.deadlettered` | `src/sqs.rs` `SqsScanOutcomeConsumer::process` | after the malformed message was copied to the DLQ |

## Evidence

- Contract parity: `tests/security_event_contract.rs` reads `../broker/contracts/` at test time (prints SKIP and passes if absent). Every constructor output validates against the schema (`jsonschema` 0.56, same as broker), and the 11 broker examples deserialize into `SecurityEvent` and round-trip exactly.
- RED SEP-02: `cargo test --lib --no-run` failed with 60 compile errors (`SecurityEvent`, `emit`, publishers not found) after writing the unit tests first.
- GREEN SEP-02: 13 `security_events` unit tests and 3 contract tests passed; clippy `-D warnings` clean.
- RED SEP-03: `cargo test --lib config` failed to compile (`parse_stream_name`, `ConfigError::InvalidStreamName` missing). The LocalStack tests (`kinesis_publisher_localstack`, `wiring_localstack`, `sqs_consumer_localstack`) were written first and did not compile until the adapter existed.
- GREEN SEP-03: `cargo test -- --ignored` for the three suites passed (Kinesis round trip with schema validation and partition keys, missing stream gives `PublishFailed` without the body, wiring publishes through `AppState.security_events`, malformed message emits `message.deadlettered` with queue and reason code only).
- RED SEP-04: the positive tests failed before the handlers emitted (`oidc_login`: login and logout; `scan_submission`: scan.requested; `rate_limiting`: ratelimit.hit). For `scan_history_and_cancellation` the emission was written before its test, so RED was checked by temporarily corrupting the emitted actor: the positive test failed, then the code was restored.
- GREEN SEP-04: every flow has a test where the publisher always fails and the HTTP response is identical (302 with cookie, 204, 200 with `scanId`, 202, 429 with the same body), and tests where no event is emitted on rejection (broker failure, bad callback, invalid logout cookie, unknown scan).
- `emit` timeout: `emit_gives_up_on_a_hanging_publisher_after_the_timeout` uses a paused tokio clock (`test-util`), no wall-clock wait.
- Dependency: `aws-sdk-kinesis` 1.125.0 is the newest release compatible with the `aws-runtime` 1.10.0 / `aws-smithy-runtime` 1.16.0 already in the lock; `Cargo.lock` changed only by additions.
- Final: `make verify` exit 0 (fmt, clippy `-D warnings`, unit and integration tests, ignored LocalStack suites, `cargo doc`); `cargo test --lib` 107 passed on three consecutive runs.
- Review: none run (stored user policy: decline; this task touches no permission or secret).

## Known limitations

- An event can be lost if the process dies (or `gateway::run` returns) before the spawned task publishes; no retry or outbox. Acceptable: events are observability facts.
- `auth.logout` with an expired or invalid cookie, and `scan.cancelled` target, are not reported (see D2, D6).
- `ratelimit.hit` volume equals the rejected-request volume; a flooding client produces one Kinesis write per rejected request (1 shard, 1000 records/s). Add sampling if KAP-11 shows pressure.

## Next step

KAP-07 (nmap-service) and KAP-08 (user-service) producers; KAP-09 consumer in the gateway.
