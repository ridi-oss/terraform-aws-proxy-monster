locals {
  db_master_username = "pmadmin"
}

module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 10.2"

  name            = var.name
  engine          = "aurora-postgresql"
  engine_mode     = "provisioned"
  engine_version  = "17.5"
  master_username = local.db_master_username
  database_name   = "proxymonster"

  # Self-managed write-only password: the module ignores master_password_wo unless
  # manage_master_user_password is off, and AWS-managed rotation (aws provider #37779)
  # can't be disabled once on, breaking control-plane's boot-cached creds.
  manage_master_user_password = false
  master_password_wo          = ephemeral.random_password.db_master.result
  master_password_wo_version  = var.db_master_password_version

  serverlessv2_scaling_configuration = {
    min_capacity = 0.5
    max_capacity = var.aurora_max_capacity
  }

  instances = {
    one = {
      instance_class = "db.serverless"
    }
  }

  create_db_subnet_group = true
  vpc_id                 = var.vpc_id
  subnets                = var.database_subnets

  security_group_ingress_rules = {
    control-plane = {
      referenced_security_group_id = module.ecs.services["control-plane"].security_group_id
    }
    # auditmon reads the audit trail from this same cluster directly, so its task security group needs
    # its own rule — it is a separate service and does not inherit the control-plane's.
    auditmon = {
      referenced_security_group_id = module.ecs.services["auditmon"].security_group_id
    }
  }

  storage_encrypted   = true
  deletion_protection = true
  apply_immediately   = true
  skip_final_snapshot = false
}
