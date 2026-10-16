# CI/CD deploy for gateway

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `ci-cd-deploy` | Engram topic: `odd/ci-cd-deploy/tasks` (project: gateway) | Branch: `v1`
- Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`, Engram topic `odd/cloud-native-deploy/tasks`
- Depends on `infra` tasks: TF-07, TF-08, TF-10, TF-12, TF-16

## Objective

Give `gateway` automated CI (format, lint, tests, image build) on pull requests and automated
CD (image build/push to ECR and ECS rollout) on pushes to `main`, and make its broker
configuration point at Amazon MQ for RabbitMQ (AMQPS 5671) instead of the self-managed RabbitMQ container.

## Why

Today the image is built and pushed by hand (`infra/deploy/aws/05`, `07`, `17`) and the task
definition is `sed`-templated from `infra/deploy/aws/task-defs/gateway.json`, with Google OAuth
credentials injected by `16-update-gateway-oauth.sh`. That is not reproducible or reviewable.

## Scope

In:

- `.aws/task-definition.json` owned by this repo (CI owns task-definition revisions).
- Broker endpoint config for Amazon MQ (AMQPS 5671).
- OAuth and signing secrets injected through task-definition `secrets`, never committed.
- `ci.yml` (pull requests) and `deploy.yml` (push to `main` + `workflow_dispatch`).
- README/docs updates.

Out:

- **Gateway architecture redesign is DEFERRED by the user.** Open question: whether and how a
  managed gateway fits. AWS API Gateway alone cannot do Google OAuth, own session issuing,
  profile provisioning, or the post-login redirect. This feature covers only CI/CD and MQ
  endpoint config; no application behavior changes.
- Terraform (owned by `infra`), MQ definitions import (owned by `broker`).
- GitHub OIDC / new IAM roles (not possible in Learner Lab).
- Push, PR creation and merge (user decisions).

## Constraints

- AWS Academy Learner Lab: no OIDC; temporary credentials stored as GitHub secrets
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, refreshed with
  `infra` `refresh-gh-secrets.sh` before each deploy. Execution role: `LabRole`.
- Terraform owns the ECS service (bootstrap task definition, `ignore_changes = [task_definition]`);
  this repo's CI owns task-definition revisions.
- Cluster `security-app-cluster-v2`, service `gateway`, log group `/ecs/security-app/gateway`.
- Broker: Amazon MQ for RabbitMQ over AMQPS 5671. OAuth/signing/broker secrets come from
  SSM Parameter Store or Secrets Manager only if infra spike 6 (`LabRole` can read them) passes; never in git.
- Current code facts (inspected):
  - `src/wiring.rs` calls `BrokerPublisher::connect` / `BrokerConsumer::connect`, which verify TLS
    against the system root CA store (`rustls-native-certs`). Amazon MQ uses a public CA, so no
    code change is expected (infra spike 4 confirms). The lab-CA path (`connect_with_ca_pem`) is test-only.
  - Config is env only: `BROKER_AMQPS_URL` (full `amqps://user:pass@host:5671`, secret, URL-encode
    the password) and `BROKER_VHOST`. The vhost must exist in Amazon MQ (imported by `broker`).

## Tooling

- Strict TDD: enabled (source: user global configuration). Observe RED before implementing.
- Runner: `make verify` (fmt check, clippy `-D warnings`, `cargo test`, `cargo test -- --ignored`, `cargo doc`).
- Workflows: `actionlint`. Docker build check in CI without push.

## Checklist

- [ ] CI-01 `.aws/task-definition.json`: Fargate, family `security-app-gateway`, port 8080, awslogs, placeholders for image and role.
- [ ] CI-02 Broker config for Amazon MQ: `BROKER_AMQPS_URL` host/port 5671 and `BROKER_VHOST`; confirm system-CA TLS works (add or adjust a test only if a gap appears).
- [ ] CI-03 Secrets via task-def `secrets` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SIGNING_KEY`, `BROKER_AMQPS_URL`, `MS_USUARIOS_SHARED_SECRET`); no plaintext values in git.
- [ ] CI-04 `.github/workflows/ci.yml` on pull request: fmt, clippy, tests, `docker build` (no push). `actionlint` clean.
- [ ] CI-05 `.github/workflows/deploy.yml` on push to `main` and `workflow_dispatch`: configure-aws-credentials, ECR login, build/push `:${{ github.sha }}`, render task definition, deploy, wait for service stability (cluster `security-app-cluster-v2`, service `gateway`).
- [ ] CI-06 Docs: README deploy/CI section, required GitHub secrets and variables, rollback note.

## Open questions

- Gateway redesign (deferred by the user): keep the Rust service as is, or put a managed gateway in front? Blocks nothing in this feature.

## Acceptance

- CI is green on a pull request; `deploy.yml` produces a stable ECS rollout of the `${{ github.sha }}` image.
- Gateway starts against Amazon MQ and publishes/consumes (`/health` ok, scan flow end to end per master plan).
- No secret values in git history of this feature.

## Checks

`make verify`; `actionlint .github/workflows/*.yml`; `docker build .`; JSON validity of `.aws/task-definition.json`.

## Progress

Planned. No checklist item started.

## Next step

CI-01 after infra TF-07/TF-08/TF-10/TF-12/TF-16 expose the cluster, service, ECR repo and MQ endpoint.
