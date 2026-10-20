# CI/CD deploy for gateway

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `ci-cd-deploy` | Engram topic: `odd/ci-cd-deploy/tasks` (project: gateway) | Branch: `feature/ci_cd`
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

- `ci.yml` (pull requests, push to `develop`) and `deploy.yml` (push to `main` + `workflow_dispatch`).
- CI owns only the image revision: the deploy job downloads the task definition the ECS service currently uses, swaps the `gateway` container image to `<ECR repo>:${{ github.sha }}`, registers it and updates the service.
- README/docs updates.

Out:

- **Gateway architecture redesign is DEFERRED by the user.** Open question: whether and how a
  managed gateway fits. AWS API Gateway alone cannot do Google OAuth, own session issuing,
  profile provisioning, or the post-login redirect. This feature covers only CI/CD and the
  messaging env config; the adapter rewrite is only `sqs-sns-adapter`, not the redesign.
- Task definition content (env, SSM secrets, roles, logging): Terraform in `infra` (TF-11/TF-12) is the single source of truth; nothing is committed here.
- Terraform (owned by `infra`), messaging topology design and tests (owned by `broker`), the adapter code (`sqs-sns-adapter`).
- GitHub OIDC / new IAM roles (not possible in Learner Lab).
- Push, PR creation and merge (user decisions).

## Constraints

- AWS Academy Learner Lab: no OIDC; temporary credentials stored as GitHub secrets
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, refreshed with
  `infra` `refresh-gh-secrets.sh` before each deploy. Execution role: `LabRole`.
- Terraform owns the ECS service (bootstrap task definition, `ignore_changes = [task_definition]`);
  this repo's CI only registers new revisions that differ from the current one in the image (Decision D1).
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

- [x] CI-01 `.aws/task-definition.json`: superseded by decision D1 (done-by-design). The task definition lives in Terraform (bootstrap revision); nothing is committed here.
- [x] CI-02 Messaging env vars: superseded by D1 (done-by-design). Env comes from the Terraform bootstrap task definition; code changes stay in `sqs-sns-adapter`.
- [x] CI-03 Secrets via task-def `secrets`: superseded by D1 (done-by-design). SSM-backed secrets come from the Terraform bootstrap task definition; no values in git.
- [x] CI-04 `.github/workflows/ci.yml` on pull request: fmt, clippy, tests, `docker build` (no push). `actionlint` clean.
- [x] CI-05 `.github/workflows/deploy.yml` on push to `main` and `workflow_dispatch`: configure-aws-credentials, ECR login, build/push `:${{ github.sha }}`, download current task definition, render (image swap), deploy, wait for service stability (cluster `security-app-cluster-v2`, service `gateway`).
- [x] CI-06 Docs: README deploy/CI section, required GitHub secrets and variables, rollback note.

## Decisions

- D1 (2026-10-19, user, option A): Terraform (`infra`, TF-11/TF-12) is the single source of truth for the task definition (env, SSM secrets, roles, logging). CI owns only the image revision: `deploy.yml` fetches the task definition the service currently uses, swaps the image to `${{ github.sha }}`, registers it and updates the service. Supersedes CI-01, CI-02, CI-03. Consequence: `deploy.yml` also pushes `:latest` because the Terraform bootstrap task definition points at it.

## Open questions

- Gateway redesign (deferred by the user): keep the Rust service as is, or put a managed gateway in front? Blocks nothing in this feature.

## Acceptance

- CI is green on a pull request; `deploy.yml` produces a stable ECS rollout of the `${{ github.sha }}` image.
- Gateway starts against SNS + SQS and publishes/consumes (`/health` ok, scan flow end to end per master plan).
- No secret values in git history of this feature.

## Checks

`make verify`; `actionlint .github/workflows/*.yml`; `docker build .`.

## Progress

CI-01..03 superseded by D1. CI-04..06 implemented locally (workflows, README CI/CD section); local checks passed. Live checks pending: green PR run and real deploy, which need the user to push/open a PR and have repo secrets/variable set.

## CI/CD evidence

Route: delegated writer (single bounded writer), Strict TDD = observable checks first.

- Baseline (before): `actionlint .github/workflows/*.yml` -> `open .github/workflows/*.yml: no such file or directory` (workflow dir absent).
- After: `mise exec actionlint@1.7.12 shellcheck@latest -- actionlint .github/workflows/*.yml` -> clean, exit 0 (shellcheck is needed for `run:` script checks).
- `make verify` -> exit 0 (fmt, clippy, tests, ignored LocalStack tests, doc).
- `docker build -t gateway:ci-check .` -> exit 0; image removed afterwards.
- Pinned actions (full commit SHA): configure-aws-credentials v6.3.0, amazon-ecr-login v2.1.7, amazon-ecs-render-task-definition v1.9.1, amazon-ecs-deploy-task-definition v2.6.4, Swatinem/rust-cache v2.9.2; `actions/checkout@v4`.
- Pending (needs user): green PR run of `ci.yml`; real `deploy.yml` rollout.

## Next step

User pushes the branch and opens a PR to verify CI live; before the first deploy run infra `refresh-gh-secrets.sh`. Adapter work: `sqs-sns-adapter` MSG-GW-01.
