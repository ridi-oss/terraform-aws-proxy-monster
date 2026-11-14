# AGENTS.md — terraform-aws-proxy-monster

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
(cd bootstrap && uv run python -m unittest)
```

The bootstrap integration tests skip unless they find throwaway servers; the
PostgreSQL ones create fixed roles, so start a fresh container per run:

```sh
docker run -d --rm --name bootstrap-pg -e POSTGRES_PASSWORD=local-bootstrap-test -p 127.0.0.1:55432:5432 postgres:16
docker run -d --rm --name bootstrap-mysql -e MYSQL_ROOT_PASSWORD=local-bootstrap-test -p 127.0.0.1:53306:3306 mysql:8.0
(cd bootstrap && POSTGRES_TEST_PORT=55432 MYSQL_TEST_PORT=53306 uv run python -m unittest)
```
