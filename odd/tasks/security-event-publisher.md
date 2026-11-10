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

- [x] SEP-01 Feature doc.
- [ ] SEP-02 `SecurityEvent` envelope, port, recorder and no-op adapters, schema parity tests (tests first).
- [ ] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, wiring, LocalStack test.
- [ ] SEP-04 Emission points with failure-isolation tests.
- [ ] SEP-05 `docs/architecture.md`, README env table, this doc closed.

## Evidence

(Filled per task.)

## Next step

KAP-07 (nmap-service) and KAP-08 (user-service) producers; KAP-09 consumer in the gateway.
