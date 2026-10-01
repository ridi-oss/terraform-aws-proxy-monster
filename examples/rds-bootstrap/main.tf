# proxy-monster in a tools account; the bootstrap function provisions the proxy's DB account on an
# Aurora cluster in a separate data account.
provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "data"
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::${var.data_account_id}:role/terraform"
  }
}

data "aws_caller_identity" "current" {}

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

  bootstrap_client_host_pattern = "10.0.%"

  target_credential_groups = {
    orders-ro = {
      aws_account_id    = var.data_account_id
      aws_account_alias = "data"
      rds_kind          = "cluster"
      rds_identifier    = "orders"
      engine            = "mysql"
      database          = "orders"
      schemas           = ["orders"]
    }
  }

  # The role that turns on managed master credentials against the rds-admin key.
  rds_admin_key_enabler_role_arns = {
    data = ["arn:aws:iam::${var.data_account_id}:role/terraform"]
  }
  target_credentials_key_admin_role_arns = [var.apply_role_arn]

  datasources = {
    orders = {
      engine           = "mysql"
      wire_port        = 40001
      tags             = "system:production"
      credential_group = "orders-ro"
      target           = { host = var.orders_cluster_endpoint, port = 3306, db = "orders" }
    }
  }

  audit_bucket_name = "example-proxy-monster-audit"
}

# In the data account: the role the bootstrap function assumes to read the RDS-managed master secret.
# The cluster itself must set manage_master_user_password = true and
# master_user_secret_kms_key_id = module.proxy_monster.rds_admin_key_arns["data"].
module "bootstrap_reader" {
  source    = "../../modules/bootstrap-reader"
  providers = { aws = aws.data }

  bootstrap_account_id = data.aws_caller_identity.current.account_id
  bootstrap_role_arn   = module.proxy_monster.bootstrap_role_arn
  rds_admin_key_arn    = module.proxy_monster.rds_admin_key_arns["data"]
  rds_arns             = var.orders_rds_arns
}
