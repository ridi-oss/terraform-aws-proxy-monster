data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  aws_account_id = data.aws_caller_identity.current.account_id
  aws_region     = data.aws_region.current.region
}

module "role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role"
  version = "~> 6.2"

  # The module prefixes by default; both the assume-role grant and the key policy match the literal.
  use_name_prefix = false
  name            = var.role_name
  description     = "proxy-monster bootstrap: read this account's RDS-managed master secrets"

  # Root plus condition: a named principal resolves to a unique id and rots on recreation.
  trust_policy_permissions = {
    AllowBootstrapFunction = {
      actions = ["sts:AssumeRole"]
      principals = [{
        type        = "AWS"
        identifiers = ["arn:aws:iam::${var.bootstrap_account_id}:root"]
      }]
      condition = [{
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [var.bootstrap_role_arn]
      }]
    }
  }

  create_inline_policy = true
  inline_policy_permissions = {
    DescribeTargets = {
      effect    = "Allow"
      actions   = ["rds:DescribeDBClusters", "rds:DescribeDBInstances"]
      resources = var.rds_arns
    }
    # RDS appends a generated suffix (rds!cluster-<uuid>), so no exact ARN can be written ahead.
    ReadManagedMasterSecrets = {
      effect    = "Allow"
      actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
      resources = ["arn:aws:secretsmanager:${local.aws_region}:${local.aws_account_id}:secret:rds!*"]
    }
    DecryptManagedMasterSecrets = {
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:DescribeKey"]
      resources = [var.rds_admin_key_arn]
    }
  }
}
