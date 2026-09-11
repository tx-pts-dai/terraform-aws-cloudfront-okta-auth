# AGENTS.md

Instructions for AI coding agents and contributors working in this repository.

## What this repo is

A public Terraform registry module (`tx-pts-dai/cloudfront-okta-auth/aws`) that protects an existing CloudFront distribution with Okta OIDC login using a single Lambda@Edge viewer-request function.

## Layout

- `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`: the module. All resources live in us-east-1 (Lambda@Edge requirement); callers pass a us-east-1 provider.
- `lambda/auth.mjs`: all OIDC, JWT and cookie logic, zero npm dependencies. `lambda/index.mjs` is the Lambda entrypoint. `lambda/config.mjs.tftpl` is the only templated file.
- `lambda/test/`: `node --test` unit tests.
- `tests/`: `terraform test` files using `mock_provider "aws"`; they run with no credentials.
- `examples/complete/`: S3 + CloudFront + this module.

## Conventions

- Conventional Commits; releases are cut by semantic-release on `main`. Mark interface changes (removed/renamed variable or output, changed default that alters live infrastructure, raised Terraform floor) as breaking (`feat!:` / `BREAKING CHANGE:`). While the module is `0.x`, `.releaserc.json` maps breaking changes to a MINOR bump; drop that rule when cutting `1.0.0`.
- Do not template `auth.mjs`; keep shipped handler code byte-identical to what the unit tests exercise.
- Never log or echo tokens, authorization codes or the client secret.
- `okta_client_secret` is ephemeral and written via `value_wo`; never reference it outside that argument (no locals, outputs or `config.mjs`).
- Run before opening a PR:

```shell
node --test "lambda/test/*.test.mjs"
terraform init -backend=false && terraform validate && terraform test
pre-commit run -a
```
