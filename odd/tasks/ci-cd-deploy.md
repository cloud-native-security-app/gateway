# CI/CD deploy for gateway

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `ci-cd-deploy` | Engram topic: `odd/ci-cd-deploy/tasks` (project: gateway) | Branch: `v1`
- Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`, Engram topic `odd/cloud-native-deploy/tasks`
- Depends on `infra` tasks: TF-07, TF-08, TF-10 (now SNS + SQS), TF-12, TF-16
- Messaging adapter rewrite (lapin -> AWS SDK) lives in repo `gateway`, path `odd/tasks/sqs-sns-adapter.md` (MSG-GW-01..04)

## Objective

Give `gateway` automated CI (format, lint, tests, image build) on pull requests and automated
CD (image build/push to ECR and ECS rollout) on pushes to `main`, and make its broker
configuration point at AWS SNS + SQS (topic ARNs, queue URL, region) instead of RabbitMQ. Amazon MQ was denied in the Learner Lab; SNS + SQS were chosen on 2026-10-17.

## Why

Today the image is built and pushed by hand (`infra/deploy/aws/05`, `07`, `17`) and the task
definition is `sed`-templated from `infra/deploy/aws/task-defs/gateway.json`, with Google OAuth
credentials injected by `16-update-gateway-oauth.sh`. That is not reproducible or reviewable.

## Scope

In:

- `.aws/task-definition.json` owned by this repo (CI owns task-definition revisions).
- Messaging env config for SNS + SQS in the task definition (topic ARNs, queue URL, region); the code that reads it is `sqs-sns-adapter`.
- OAuth and signing secrets injected through task-definition `secrets`, never committed.
- `ci.yml` (pull requests) and `deploy.yml` (push to `main` + `workflow_dispatch`).
- README/docs updates.

Out:

- **Gateway architecture redesign is DEFERRED by the user.** Open question: whether and how a
  managed gateway fits. AWS API Gateway alone cannot do Google OAuth, own session issuing,
  profile provisioning, or the post-login redirect. This feature covers only CI/CD and the
  messaging env config; the adapter rewrite is only `sqs-sns-adapter`, not the redesign.
- Terraform (owned by `infra`), messaging topology design and tests (owned by `broker`), the adapter code (`sqs-sns-adapter`).
- GitHub OIDC / new IAM roles (not possible in Learner Lab).
- Push, PR creation and merge (user decisions).

## Constraints

- AWS Academy Learner Lab: no OIDC; temporary credentials stored as GitHub secrets
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, refreshed with
  `infra` `refresh-gh-secrets.sh` before each deploy. Execution role: `LabRole`.
- Terraform owns the ECS service (bootstrap task definition, `ignore_changes = [task_definition]`);
  this repo's CI owns task-definition revisions.
- Cluster `security-app-cluster-v2`, service `gateway`, log group `/ecs/security-app/gateway`.
- Messaging: AWS SNS + SQS over HTTPS (public CA). Credentials come from the ECS task role (`LabRole`, shared by all services:
  no per-service least privilege). OAuth/signing secrets come from SSM Parameter Store or Secrets Manager only if infra spike 6
  (`LabRole` can read them) passes; never in git.
- Config (superseded 2026-10-17): the previous `BROKER_AMQPS_URL` (secret AMQPS URL) and `BROKER_VHOST` are replaced by non-secret
  variables, proposed `AWS_REGION`, `SCAN_REQUESTS_TOPIC_ARN`, `SCAN_CANCELLATIONS_TOPIC_ARN`, `GATEWAY_SCAN_OUTCOMES_QUEUE_URL`
  (final names in `sqs-sns-adapter` MSG-GW-01). The old `lapin` code paths (`BrokerPublisher::connect`, lab-CA helper) go away in MSG-GW-04.

## Tooling

- Strict TDD: enabled (source: user global configuration). Observe RED before implementing.
- Runner: `make verify` (fmt check, clippy `-D warnings`, `cargo test`, `cargo test -- --ignored`, `cargo doc`).
- Workflows: `actionlint`. Docker build check in CI without push.

## Checklist

- [ ] CI-01 `.aws/task-definition.json`: Fargate, family `security-app-gateway`, port 8080, awslogs, placeholders for image and role.
- [ ] CI-02 Messaging env vars in the task definition: topic ARNs, queue URL and region from `infra` outputs (TF-15). Code changes are tracked in `sqs-sns-adapter` (MSG-GW-01..04); depends on MSG-GW-01. (Replaces the superseded Amazon MQ item `BROKER_AMQPS_URL` / `BROKER_VHOST`.)
- [ ] CI-03 Secrets via task-def `secrets` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SIGNING_KEY`, `MS_USUARIOS_SHARED_SECRET`; the broker URL secret is gone with SQS/SNS); no plaintext values in git.
- [ ] CI-04 `.github/workflows/ci.yml` on pull request: fmt, clippy, tests, `docker build` (no push). `actionlint` clean.
- [ ] CI-05 `.github/workflows/deploy.yml` on push to `main` and `workflow_dispatch`: configure-aws-credentials, ECR login, build/push `:${{ github.sha }}`, render task definition, deploy, wait for service stability (cluster `security-app-cluster-v2`, service `gateway`).
- [ ] CI-06 Docs: README deploy/CI section, required GitHub secrets and variables, rollback note.

## Open questions

- Gateway redesign (deferred by the user): keep the Rust service as is, or put a managed gateway in front? Blocks nothing in this feature.

## Acceptance

- CI is green on a pull request; `deploy.yml` produces a stable ECS rollout of the `${{ github.sha }}` image.
- Gateway starts against SNS + SQS and publishes/consumes (`/health` ok, scan flow end to end per master plan).
- No secret values in git history of this feature.

## Checks

`make verify`; `actionlint .github/workflows/*.yml`; `docker build .`; JSON validity of `.aws/task-definition.json`.

## Progress

Planned. No checklist item started.

## Next step

CI-01 after infra TF-07/TF-08/TF-10/TF-12/TF-16 expose the cluster, service, ECR repo and messaging outputs. Adapter work: `sqs-sns-adapter` MSG-GW-01.
