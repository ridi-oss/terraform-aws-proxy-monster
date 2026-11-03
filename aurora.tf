locals {
  db_master_username = "pmadmin"
  aurora_engine      = "aurora-postgresql"
}

module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 10.2"

  name            = var.name
  engine          = local.aurora_engine
  engine_mode     = "provisioned"
  engine_version  = var.aurora_engine_version
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

  instances = {}

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

resource "aws_rds_cluster_instance" "aurora" {
  identifier                 = "${var.name}-one"
  cluster_identifier         = module.aurora.cluster_id
  engine                     = local.aurora_engine
  engine_version             = var.aurora_instance_engine_version
  instance_class             = "db.serverless"
  db_subnet_group_name       = module.aurora.db_subnet_group_name
  auto_minor_version_upgrade = false
  apply_immediately          = true
  copy_tags_to_snapshot      = true
  monitoring_interval        = 0

  lifecycle {
    create_before_destroy = true
  }
}
