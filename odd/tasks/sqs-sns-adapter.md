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
- At-least-once delivery: the handler must tolerate duplicates. Decision (user, 2026-10-19, option A): the SQS consumer deletes a message only after `handler.handle` returns; a crash mid-handle redelivers it and after 3 receives it lands in the DLQ. A duplicate only re-sends the SSE event and re-applies the same status in user-service. Today's AMQP consumer acks before `handle` (replaced).
- Proposed env vars (confirm at MSG-GW-01): `AWS_REGION`, `AWS_ENDPOINT_URL` (LocalStack only), `SCAN_REQUESTS_TOPIC_ARN`,
  `SCAN_CANCELLATIONS_TOPIC_ARN`, `GATEWAY_SCAN_OUTCOMES_QUEUE_URL`.
- Message size limit 256 KB; scan request bodies carry SSH credentials: never log bodies.
- Planning heuristic about 400 authored changed lines per task; not a cap.
- Conventional Commits, no AI attribution; push/PR/merge are user decisions.

## Checklist

- [x] MSG-GW-01 Config: parse the SQS/SNS variables (typed errors, no secrets in `Debug`), RED: config tests first. `BROKER_*` removal moves to MSG-GW-04 so the build stays green.
- [x] MSG-GW-02 Publisher on `aws-sdk-sns`: publish `ScanRequest` / `ScanCancellation` with the `routing_key` attribute; LocalStack test verifies the body and attribute reach the subscribed queue.
- [x] MSG-GW-03 Consumer on `aws-sdk-sqs` for `gateway-scan-outcomes`: long poll, delete after success, malformed handling, redrive to DLQ after 3 receives (LocalStack test), graceful shutdown replacing the AMQP reconnect loop.
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

## MSG-GW-01 evidence

- Route: delegated writer (single bounded writer, parent reviews). `BROKER_*` kept until MSG-GW-04.
- RED: `cargo test --lib config` -> compile failure (`could not compile gateway (lib test)`, 28 errors: missing `ENV_AWS_*` / `ENV_SCAN_*` constants, `Config` fields and `ConfigError::InvalidArn`).
- GREEN: `cargo test --lib config` -> 14 passed, 0 failed (7 new/extended tests: new fields load, optional endpoint Some/invalid, empty region, malformed topic ARNs, malformed queue URLs, all new vars in the Missing loop).
- Full: `cargo fmt --check` ok; `cargo clippy --all-targets -- -D warnings` clean; `cargo test` all non-ignored pass (72 unit); `cargo doc --no-deps` ok.
- Change: `src/config.rs` adds `aws_region`, `aws_endpoint_url: Option<Url>`, `scan_requests_topic_arn`, `scan_cancellations_topic_arn`, `scan_outcomes_queue_url: Url`, `scan_outcomes_dlq_url: Url`, `ConfigError::InvalidArn { name }` (value never echoed); README env table gains the 6 vars.

## MSG-GW-02 evidence

- Route: delegated writer (single bounded writer, parent reviews). `lapin`/`BrokerPublisher`/wiring untouched (wiring switches in MSG-GW-04).
- RED: `cargo test --lib sns` -> compile failure (2 errors: `BrokerError::SnsPublishFailed` and `routing_key_attribute` missing); `cargo test --test sns_publisher_localstack --no-run` -> compile failure (`gateway::sns` / `SnsScanPublisher` missing).
- GREEN: `cargo test --lib` -> 74 passed (2 new: attribute is a `String` attribute; `SnsPublishFailed` Display + source chain + not a connection error). `cargo test --test sns_publisher_localstack -- --ignored` -> 2 passed (body/attribute reach each raw-subscribed SQS queue; missing topic yields `SnsPublishFailed`).
- LocalStack image: `localstack/localstack:4.4` (runs without an auth token; readiness = `Ready.` log line).
- Dependencies: `aws-config 1.12.0` (`behavior-version-latest`), `aws-sdk-sns 1.116.0`; `aws-sdk-sqs 1.114.0` as a dev-dependency only (MSG-GW-03 promotes it to a normal dependency).
- Change: new `src/sns.rs` (`SnsScanPublisher::{from_client, connect}`, implements `ScanRequestPublisher`, `routing_key` String attribute, bodies never logged, 256 KB limit documented); `BrokerError::SnsPublishFailed { topic, source: Box<dyn Error + Send + Sync> }`; `pub mod sns` in `src/lib.rs`; `tests/sns_publisher_localstack.rs`; Makefile comment.

## MSG-GW-03 evidence

- Route: delegated writer (single bounded writer, parent reviews). `lapin`, `BrokerConsumer` and `src/wiring.rs` untouched (switch in MSG-GW-04).
- RED: `cargo test --test sqs_consumer_localstack --no-run` -> compile failure (`E0432 unresolved import gateway::sqs`, `could not compile gateway (test "sqs_consumer_localstack")`).
- GREEN: `cargo test --lib` -> 76 passed (2 new: backoff progression 1,2,4,8,16,30,30; `routing_key` extraction). `cargo test --test sqs_consumer_localstack -- --ignored` -> 5 passed in ~23 s (valid handled once + deleted; malformed to DLQ with body and `routing_key` intact and gone from source, handler never called; abort mid-`handle` leaves the message undeleted and it is redelivered; 3 receives without delete end in the DLQ via the real RedrivePolicy `maxReceiveCount: 3`; cancelling the token stops `run` during long poll in < 5 s).
- Dependencies: `aws-sdk-sqs 1.114.0` promoted to a normal dependency; `tokio-util 0.7` (`CancellationToken`, already transitive) and tokio feature `time` added.
- Design: `src/sqs.rs` `SqsScanOutcomeConsumer::{from_client, connect, run(handler, CancellationToken)}`. Delete-after-handle for valid events. Malformed: explicit `SendMessage` of the original body to the DLQ (keeps `routing_key`), then delete from source; if the DLQ send fails the message is not deleted (redrive handles it). Receive errors: logged, exponential backoff 1 s..30 s, loop only exits on shutdown. Shutdown: the token races the long poll and the backoff; an in-flight `handle` finishes first and unprocessed messages of the batch reappear after their visibility timeout. Logs never include bodies (error, `routing_key`, length only). New `BrokerError::SqsFailed { queue, #[source] Box<dyn Error + Send + Sync> }`.
- Test technique: "not deleted before handle completes" is proven by a handler that never completes and aborting the `run` task (simulated crash), then re-receiving the same message. Redrive is proven by receiving 3 times directly with the SDK (visibility 1 s) and then observing the message in the DLQ; LocalStack 4.4 moved it promptly, no long sleeps needed.
