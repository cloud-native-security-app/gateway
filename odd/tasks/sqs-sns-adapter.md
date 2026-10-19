# Feature: sqs-sns-adapter (gateway)

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `sqs-sns-adapter` | Engram topic: `odd/sqs-sns-adapter/tasks` (project: gateway; mirror pending) | Branch: `v1`
- Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`
- Topology and contract (Proposed): repo `broker`, path `odd/tasks/sqs-sns-migration.md` (MSG-01 sign-off gates this feature)
- Counterpart: repo `nmap-service`, path `odd/tasks/sqs-sns-adapter.md`
- Decision date: 2026-10-17 (RabbitMQ replaced by SNS + SQS)

## Objective

Replace the `lapin` (AMQP) messaging adapter in `gateway` with the AWS SDK for Rust (`aws-sdk-sns` to publish,
`aws-sdk-sqs` to consume), keeping the domain-facing ports and the JSON message bodies unchanged.

## Problem

`src/broker.rs` implements `BrokerPublisher` (publish to exchanges `scan.requests` / `scan.cancellations` with routing
keys `scan.request` / `scan.cancellation`) and `BrokerConsumer` (consume queue `gateway.scan-outcomes`, ack, `nack(requeue=false)`
on malformed bodies, reconnect loop). `src/wiring.rs` connects both from `BROKER_AMQPS_URL` and `BROKER_VHOST`. None of this
exists in SNS/SQS.

## Why

Amazon MQ is denied in the Learner Lab and the user chose managed SNS + SQS to demonstrate a cloud-native architecture.

## Scope

In:
- Config: region, SNS topic ARNs, SQS queue URL, optional endpoint override for LocalStack (proposed names below).
- Publisher on SNS with the `routing_key` String message attribute (`scan.request`, `scan.cancellation`).
- Consumer on SQS: long polling, delete after a successful handle, malformed-message policy per broker Q5, idempotent handling.
- Remove `lapin`, the AMQP reconnect code, `BROKER_AMQPS_URL`, `BROKER_VHOST` and lab-CA test helpers.
- Tests against LocalStack (real container, no mocks); compose gains LocalStack.

Out:
- **Gateway architecture redesign: still DEFERRED by the user.** This feature is only the messaging adapter.
- Message contracts (unchanged), topology and Terraform (`broker` design, `infra` TF-10).

## Constraints

- Strict TDD: observe RED before implementing. Runner: `cargo test`; integration tests (`-- --ignored`, Docker) use LocalStack.
- Credentials come from the default AWS provider chain (ECS task role = shared `LabRole`); never static keys in config.
- At-least-once delivery: the handler must tolerate duplicates; today the consumer acks before `handler.handle` (to be revisited).
- Proposed env vars (confirm at MSG-GW-01): `AWS_REGION`, `AWS_ENDPOINT_URL` (LocalStack only), `SCAN_REQUESTS_TOPIC_ARN`,
  `SCAN_CANCELLATIONS_TOPIC_ARN`, `GATEWAY_SCAN_OUTCOMES_QUEUE_URL`.
- Message size limit 256 KB; scan request bodies carry SSH credentials: never log bodies.
- Planning heuristic about 400 authored changed lines per task; not a cap.
- Conventional Commits, no AI attribution; push/PR/merge are user decisions.

## Checklist

- [ ] MSG-GW-01 Config: parse the SQS/SNS variables (typed errors, no secrets in `Debug`), remove `BROKER_*` config; RED: config tests first.
- [ ] MSG-GW-02 Publisher on `aws-sdk-sns`: publish `ScanRequest` / `ScanCancellation` with the `routing_key` attribute; LocalStack test verifies the body and attribute reach the subscribed queue.
- [ ] MSG-GW-03 Consumer on `aws-sdk-sqs` for `gateway-scan-outcomes`: long poll, delete after success, malformed handling, redrive to DLQ after 3 receives (LocalStack test), graceful shutdown replacing the AMQP reconnect loop.
- [ ] MSG-GW-04 Wiring and cleanup: update `src/wiring.rs`, drop `lapin` and `lapin`-related dependencies from `Cargo.toml`, LocalStack in `docker-compose` and README, `make verify` green.

## Acceptance criteria

- Gateway publishes scan requests/cancellations and consumes outcomes through SNS + SQS on LocalStack and on AWS.
- A malformed or repeatedly failing outcome ends in the DLQ; duplicates do not corrupt state.
- No `lapin` or AMQP configuration remains; `make verify` passes.

## Checks

`cargo test`; `cargo test -- --ignored` (LocalStack); `make verify`.

## Progress

Planned. Blocked on broker MSG-01 (topology sign-off) for final names and on MSG-02 (LabRole from ECS) for the AWS run.

## Next step

MSG-GW-01 once broker MSG-01 is signed off (config can start with the proposed names).
