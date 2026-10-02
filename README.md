# terraform-aws-proxy-monster

Terraform module that runs [proxy-monster](https://github.com/ridi-oss/proxy-monster)
on AWS: ECS Fargate services, an internal ALB for the console, an internal NLB
for the SQL wire, Aurora PostgreSQL for the control-plane store, an Object Lock
S3 bucket for the audit trail, and a Lambda that provisions the proxy's account
on each target database.

Architecture, inputs the caller brings, and manual steps: [docs/architecture.md](docs/architecture.md).

## Usage

```hcl
module "proxy_monster" {
  source = "git::https://github.com/ridi-oss/terraform-aws-proxy-monster.git?ref=v0.1.0"

  vpc_id           = "vpc-..."
  vpc_cidr         = "10.0.0.0/16"
  private_subnets  = ["subnet-...", "subnet-..."]
  database_subnets = ["subnet-...", "subnet-..."]

  console_hostname = "pm.example.com" # an ISSUED *.example.com ACM cert must exist

  images = {
    control_plane = "public.ecr.aws/w1t1s2q1/pm-control-plane:0.1.28"
    proxy         = "public.ecr.aws/w1t1s2q1/pm-goproxy:0.1.28"
    web           = "public.ecr.aws/w1t1s2q1/pm-web:0.1.28"
    auditmon      = "public.ecr.aws/w1t1s2q1/pm-auditmon:0.1.28"
  }

  datasources = {
    app = {
      engine    = "mysql"
      wire_port = 40001
      tags      = "system:production"
      target    = { host = "app-db.internal", port = 3306, db = "app" }
    }
  }

  audit_bucket_name = "my-proxy-monster-audit"
}
```

The reader role for a target in another account:

```hcl
module "bootstrap_reader" {
  source = "git::https://github.com/ridi-oss/terraform-aws-proxy-monster.git//modules/bootstrap-reader?ref=v0.1.0"
  # ...
}
```

Examples: [`examples/basic`](examples/basic) (hand-filled target credential),
[`examples/rds-bootstrap`](examples/rds-bootstrap) (cross-account RDS target
provisioned by the bootstrap Lambda).

## After the first apply

1. Fill `<name>/wire-tls` with the commands in the `wire_tls_issuance` output.
2. Fill `<name>/oidc-client-secret` from your IdP app.
3. Point `console_hostname` at the `console_alb_dns_name` output.
4. Fill `<name>/target-credentials/<ds>` for each datasource without a `credential_group`.

## Requirements

Terraform `~> 1.13`, AWS provider `~> 6.0`. Building the bootstrap Lambda
payload runs `bootstrap/build.sh` at plan time, which needs `bash`, `curl`,
`tar`, `sha256sum`, and `python3` (it fetches a pinned `uv`).

## Versioning

Releases are annotated `vX.Y.Z` tags on `main`, pushed by a repository admin; callers pin one
with `?ref=`. Its GitHub release notes name the proxy-monster server version it was
tested against; image tags stay the caller's choice.

## License

Apache-2.0.
