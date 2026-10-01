# AGENTS.md — proxy-monster-terraform

The AWS Terraform module for [proxy-monster](https://github.com/ridi-oss/proxy-monster).
Architecture: [docs/architecture.md](docs/architecture.md).

## Layout

- Root (`*.tf`) — the module: one proxy-monster stack.
- `bootstrap/` — Python Lambda source for target-credential provisioning, with its tests.
- `modules/bootstrap-reader/` — IAM role applied in each target account.
- `examples/` — runnable callers; CI runs `terraform validate` on each.

## Rules

- This repository is public. No organization-specific names, account IDs,
  hostnames, or topology — use `example.com`, `10.0.0.0/16`, placeholder IDs.
  Everything deployment-specific is a variable the caller sets.
- Comments state a constraint the code cannot; no history, no review narration.
- A breaking variable change is a major version bump, with the migration in the
  release notes.

## Check

```sh
terraform fmt -check -recursive
for d in . modules/bootstrap-reader examples/*; do terraform -chdir=$d init -backend=false && terraform -chdir=$d validate; done
(cd bootstrap && uv run pytest)
```
