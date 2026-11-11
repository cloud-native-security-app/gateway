# finding-port (KAP-07b, gateway part)

Feature id: `finding-port` | Branch: `feature/finding_port` (from `origin/develop`)

Sibling repos, same feature id: `broker` (contract, D-15), `nmap-service` (producer), `user-service` (storage).

## Objective

The gateway accepts and relays the optional `port`/`protocol` of a `VulnFinding` (scan outcome relay, report) and accepts a nullable `port`/`protocol` in `finding.critical` (admin feed), so the report and the admin panel can say where a vulnerability is.

## Scope

- `domain::VulnFinding.port: Option<u16>`, `.protocol: Option<String>` (omitted when `None`, same as `confidence`/`patch_state`); OpenAPI schemas follow from `ToSchema`.
- `event_contract`: `finding.critical` accepts `port`/`protocol` `null` (matches broker D-15).
- `admin::CriticalFinding.port/protocol` become `Option` (serialized as `null`).
- Contract tests against the sibling `../broker` checkout (new `tests/scan_outcome_contract.rs`, differential test already covers the event schema).
- Out of scope: producing the events (nmap-service), storage (user-service), the front.

## Constraints

- Backward compatible: findings without the fields decode and re-serialize identically.
- `VulnFinding` keeps `deny_unknown_fields`: deploy order is gateway first, then nmap-service (otherwise every `completed` outcome with a port would fail to parse and go to the DLQ).
- Unit tests: no env mutation, no waits. Comments in neutral Spanish, identifiers in English.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test` for the loop).
- Route: delegated direct, single writer.

## Decisions

- D1 `protocol` stays a `String` like `PortFinding.protocol` and `severity`: the broker schema (validated upstream) owns the closed set `tcp|udp`; the gateway relays verbatim.
- D2 `port` is a `u16`: out-of-range values (70000) fail to decode and go to the DLQ. Port 0 is accepted here (as in `PortFinding`); the broker schema is the stricter gate.
- D3 An explicit `null` decodes as `None` and is re-serialized as an absent field (equivalent meaning).

## Checklist

| ID | Task | Done |
|---|---|---|
| FP-01 | Feature document | [x] 3a813d5 |
| FP-02 | RED: tests (domain, event_contract, admin aggregator, broker schema parity) | [x] `cargo test --lib`: 11 compile errors (fields missing) |
| FP-03 | GREEN: domain, event_contract, admin | [x] `cargo test`: all suites pass (lib 150) incl. parity against broker `feature/finding_port` |
| FP-04 | Docs: decisions D-17 | [x] |
| FP-05 | `make verify` | [x] exit 0; feature commit d14215b |

## Compatibility note

Merge order is free for tests (the sibling-schema tests skip when `../broker` is absent). Runtime deploy order: gateway before nmap-service.
