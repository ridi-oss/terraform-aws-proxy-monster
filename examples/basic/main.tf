# An existing VPC, one MySQL target whose credential is filled by hand.
provider "aws" {
  region = "us-east-1"
}

module "proxy_monster" {
  source = "../.."

  vpc_id           = var.vpc_id
  vpc_cidr         = var.vpc_cidr
  private_subnets  = var.private_subnets
  database_subnets = var.database_subnets

  console_hostname = "pm.example.com"

  images = {
    control_plane = "public.ecr.aws/w1t1s2q1/pm-control-plane:${var.image_tag}"
    proxy         = "public.ecr.aws/w1t1s2q1/pm-goproxy:${var.image_tag}"
    web           = "public.ecr.aws/w1t1s2q1/pm-web:${var.image_tag}"
    auditmon      = "public.ecr.aws/w1t1s2q1/pm-auditmon:${var.image_tag}"
  }

  oidc = {
    issuer    = "https://idp.example.com"
    client_id = "proxy-monster"
    group_map = "pm-admins=system:admin,pm-developers=developers"
  }

  datasources = {
    app = {
      engine    = "mysql"
      wire_port = 40001
      tags      = "system:production"
      target    = { host = "app-db.internal.example.com", port = 3306, db = "app" }
    }
  }

  audit_bucket_name = "example-proxy-monster-audit"
}

output "console_url" {
  value = module.proxy_monster.console_url
}

output "wire_endpoints" {
  value = module.proxy_monster.wire_endpoints
}

output "wire_tls_issuance" {
  value = module.proxy_monster.wire_tls_issuance
}
