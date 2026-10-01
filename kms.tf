module "audit_signer_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.0"

  description = "proxy-monster auditmon anchor signer"

  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false

  aliases = ["${var.name}/audit-signer"]
}

module "target_credentials_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.0"

  count = local.bootstrap_enabled ? 1 : 0

  description = "proxy-monster backend DB credentials"

  enable_default_policy = true
  enable_key_rotation   = true

  key_statements = [
    {
      # The Deny stays broad: any principal or condition narrowing only widens what escapes it.
      sid       = "DenyRead"
      effect    = "Deny"
      actions   = ["kms:CreateGrant", "kms:Decrypt", "kms:ReEncryptFrom"]
      resources = ["*"]
      principals = [{
        type        = "AWS"
        identifiers = ["*"]
      }]
      condition = [{
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = local.target_credentials_key_users
      }]
    },
  ]

  # Per-secret grant Allows (the Deny still overrides); unique-id names replace grants on role recreation.
  grants = merge(
    {
      for key, ds in local.bootstrapped : "bootstrap-write-${key}" => {
        name              = "bootstrap-write-${key}-${module.bootstrap[0].lambda_role_unique_id}"
        grantee_principal = module.bootstrap[0].lambda_role_arn
        operations        = ["DescribeKey", "Encrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"]
        constraints = [{
          encryption_context_subset = { SecretARN = aws_secretsmanager_secret.target_credentials[key].arn }
        }]
      }
    },
    {
      for key, ds in local.bootstrapped : "proxy-read-${key}" => {
        name              = "proxy-read-${key}-${module.ecs.services["proxy-${key}"].task_exec_iam_role_unique_id}"
        grantee_principal = module.ecs.services["proxy-${key}"].task_exec_iam_role_arn
        operations        = ["Decrypt", "DescribeKey"]
        constraints = [{
          encryption_context_subset = { SecretARN = aws_secretsmanager_secret.target_credentials[key].arn }
        }]
      }
    },
  )

  aliases = ["${var.name}/target-credentials"]
}

module "rds_admin_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 4.0"

  for_each = local.rds_admin_account_ids

  description = "proxy-monster RDS managed master user secret (${each.key})"

  enable_default_policy = true
  enable_key_rotation   = true

  key_statements = concat(
    # Statement-gated: IAM ignores empty condition value lists, opening the Allow to anyone.
    length(lookup(var.rds_admin_key_enabler_role_arns, each.key, [])) == 0 ? [] : [
      {
        sid       = "AllowRdsEnablement"
        effect    = "Allow"
        actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
        resources = ["*"]
        principals = [{
          type        = "AWS"
          identifiers = ["arn:aws:iam::${each.value}:root"]
        }]
        condition = [{
          test     = "ArnEquals"
          variable = "aws:PrincipalArn"
          values   = lookup(var.rds_admin_key_enabler_role_arns, each.key, [])
        }]
      },
      {
        # Split out: kms:GrantIsForAWSResource exists only in CreateGrant's request context.
        sid       = "AllowRdsEnablementGrant"
        effect    = "Allow"
        actions   = ["kms:CreateGrant"]
        resources = ["*"]
        principals = [{
          type        = "AWS"
          identifiers = ["arn:aws:iam::${each.value}:root"]
        }]
        condition = [
          {
            test     = "ArnEquals"
            variable = "aws:PrincipalArn"
            values   = lookup(var.rds_admin_key_enabler_role_arns, each.key, [])
          },
          {
            test     = "Bool"
            variable = "kms:GrantIsForAWSResource"
            values   = ["true"]
          },
        ]
      },
    ],
    [
      {
        sid       = "AllowBootstrapRead"
        effect    = "Allow"
        actions   = ["kms:Decrypt", "kms:DescribeKey"]
        resources = ["*"]
        principals = [{
          type        = "AWS"
          identifiers = ["arn:aws:iam::${each.value}:root"]
        }]
        condition = [
          {
            test     = "ArnEquals"
            variable = "aws:PrincipalArn"
            values   = ["arn:aws:iam::${each.value}:role/${local.reader_role_name}"]
          },
          {
            test     = "StringEquals"
            variable = "kms:ViaService"
            values   = ["secretsmanager.${local.aws_region}.amazonaws.com"]
          },
        ]
      },
      {
        # RDS rotates through a grant; explicit Deny beats a grant, and failed rotation is quiet.
        sid       = "DenyRead"
        effect    = "Deny"
        actions   = ["kms:CreateGrant", "kms:Decrypt", "kms:ReEncryptFrom"]
        resources = ["*"]
        principals = [{
          type        = "AWS"
          identifiers = ["*"]
        }]
        condition = [
          {
            test     = "ArnNotEquals"
            variable = "aws:PrincipalArn"
            values = concat(
              ["arn:aws:iam::${each.value}:role/${local.reader_role_name}"],
              lookup(var.rds_admin_key_enabler_role_arns, each.key, []),
            )
          },
          {
            test     = "Bool"
            variable = "aws:PrincipalIsAWSService"
            values   = ["false"]
          },
        ]
      },
  ])

  aliases = ["${var.name}/rds-admin/${each.key}"]
}
