locals {
  seal_audit_metric_namespace = "ProxyMonster/SealAudit"
  seal_audit_metric_name      = "Events"

  # Injected only for calls the handler itself makes; the trust policy and the ENI call never carry it.
  bootstrap_source_function = [{
    test     = "ArnEquals"
    variable = "lambda:SourceFunctionArn"
    values   = ["arn:aws:lambda:${local.aws_region}:${local.aws_account_id}:function:${var.name}-bootstrap"]
  }]

  bootstrap_config = {
    secret_prefix = "${var.name}/target-credentials/"
    ecs_cluster   = var.name
    groups = {
      for name, group in var.target_credential_groups : name => {
        reader_role_arn = try(local.reader_role_arns[name], null)
        rds_kind        = group.rds_kind
        rds_identifier  = group.rds_identifier
        external_host   = group.external_host
        external_port   = group.external_port
        external_ca_pem = group.external_ca_pem

        external_ca_strict_extensions = group.external_ca_strict_extensions
        # The name, not the resource ARN. A new secret's ARN is unknown until apply, which would
        # defer the build data sources, leave the zip absent at plan, and so plan the function as a
        # no-op that apply never revisits: the handler would silently stay on the old code.
        master_secret_name = (
          group.external_host == null
          ? null
          : "${var.name}/master-credentials/${group.external_identifier}"
        )
        engine                            = group.engine
        database                          = group.database
        schemas                           = group.schemas
        privileges                        = group.privileges
        system_schemas                    = group.system_schemas
        system_routines                   = group.system_routines
        drop_tables                       = group.drop_tables
        global_privileges                 = group.global_privileges
        username                          = group.username
        postgres_role                     = group.postgres_role
        postgres_role_create              = group.postgres_role_create
        postgres_role_database_privileges = group.postgres_role_database_privileges
        host_pattern                      = var.bootstrap_client_host_pattern
        datasources = {
          for key, ds in local.bootstrapped : key => ds.target.host if ds.credential_group == name
        }
      }
    }
  }
}

module "bootstrap_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 6.0"

  count = local.bootstrap_enabled ? 1 : 0

  name            = "${var.name}-bootstrap"
  description     = "proxy-monster bootstrap function"
  use_name_prefix = false
  vpc_id          = var.vpc_id

  egress_rules = {
    all = {
      description = "Backend DB, STS, RDS and Secrets Manager APIs via NAT"
      cidr_ipv4   = "0.0.0.0/0"
      ip_protocol = "-1"
    }
  }

  tags = {
    Name = "${var.name}-bootstrap"
  }
}

data "http" "rds_ca_bundle" {
  count = local.bootstrap_enabled ? 1 : 0

  url = "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"

  lifecycle {
    postcondition {
      condition = (
        self.status_code == 200 && can(regex("-----BEGIN CERTIFICATE-----", self.response_body))
      )
      error_message = "RDS global CA bundle did not come back as PEM (status ${self.status_code})."
    }
  }
}

# Data sources so the payload exists at both plan and apply on fresh CI checkouts.
#
# bootstrap_config ships inside the archive rather than as an environment variable because it grows
# with every credential group: nine groups already render 4993 bytes, and UpdateFunctionConfiguration
# rejects the whole request above 5120, so the tenth group cannot be deployed at all. The archive has
# four orders of magnitude more headroom, and a config change stays one atomic code deployment that
# the seal-audit rule already watches (UpdateFunctionCode), which an SSM or S3 hand-off would not.
data "external" "bootstrap_build" {
  count = local.bootstrap_enabled ? 1 : 0

  program = ["bash", "${path.module}/bootstrap/build.sh"]

  query = {
    bootstrap_config = jsonencode(local.bootstrap_config)
    ca_bundle        = data.http.rds_ca_bundle[0].response_body
  }
}

data "archive_file" "bootstrap" {
  count = local.bootstrap_enabled ? 1 : 0

  type        = "zip"
  source_dir  = data.external.bootstrap_build[0].result.payload_dir
  output_path = "${path.module}/.build/bootstrap.zip"
}

module "bootstrap" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.17"

  count = local.bootstrap_enabled ? 1 : 0

  function_name = "${var.name}-bootstrap"
  handler       = "handler.handler"
  runtime       = "python3.14"
  architectures = ["arm64"]

  create_package         = false
  local_existing_package = data.archive_file.bootstrap[0].output_path

  timeout     = 300
  memory_size = 512

  # Two concurrent runs for one group would race ALTER USER and strand a password in the secret.
  reserved_concurrent_executions = 1

  vpc_subnet_ids = var.private_subnets
  vpc_security_group_ids = concat(
    [module.bootstrap_sg[0].id],
    var.bootstrap_security_group_ids,
  )
  attach_network_policy = true

  role_name        = local.bootstrap_role_name
  role_description = "proxy-monster bootstrap function"

  attach_policy_statements = true
  policy_statements = merge(
    # Either is empty when every group is backed the other way, and a resourceless statement is invalid.
    length(local.reader_role_arns) == 0 ? {} : {
      AssumeTargetReaders = {
        effect    = "Allow"
        actions   = ["sts:AssumeRole"]
        resources = values(local.reader_role_arns)
        condition = local.bootstrap_source_function
      }
    },
    length(local.external_master_secrets) == 0 ? {} : {
      ReadMasterCredentials = {
        effect  = "Allow"
        actions = ["secretsmanager:GetSecretValue"]
        resources = [
          for identifier in keys(local.external_master_secrets) :
          aws_secretsmanager_secret.master_credentials[identifier].arn
        ]
        condition = local.bootstrap_source_function
      }
    },
    {
      PublishTargetCredentials = {
        effect  = "Allow"
        actions = ["secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue"]
        resources = [
          for key, ds in local.bootstrapped : aws_secretsmanager_secret.target_credentials[key].arn
        ]
        condition = local.bootstrap_source_function
      }
      RestartProxies = {
        effect  = "Allow"
        actions = ["ecs:UpdateService"]
        resources = [
          for key, ds in local.bootstrapped :
          "arn:aws:ecs:${local.aws_region}:${local.aws_account_id}:service/${var.name}/proxy-${key}"
        ]
        condition = local.bootstrap_source_function
      }

      # attach_network_policy copies AWSLambdaENIManagementAccess, which predates this requirement.
      DescribeSubnetsForEni = {
        effect    = "Allow"
        actions   = ["ec2:DescribeSubnets"]
        resources = ["*"]
      }
    },
  )

  cloudwatch_logs_retention_in_days = 365
}

module "seal_audit_logs" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version = "~> 5.0"

  count = local.bootstrap_enabled ? 1 : 0

  name              = "/aws/events/${var.name}-seal-audit"
  retention_in_days = 400
}

# Broad on purpose: CloudTrail renders targets inconsistently and suffixes lambda event names.
module "seal_audit" {
  source  = "terraform-aws-modules/eventbridge/aws"
  version = "~> 3.13"

  count = local.bootstrap_enabled ? 1 : 0

  create_bus          = false
  append_rule_postfix = false

  rules = {
    "${var.name}-seal-audit" = {
      description = "Policy changes that could open a read path to a proxy-monster credential"
      event_pattern = jsonencode({
        detail-type = ["AWS API Call via CloudTrail"]
        source      = ["aws.kms", "aws.lambda", "aws.secretsmanager"]
        detail = {
          eventName = [
            "CreateGrant",
            "DeleteResourcePolicy",
            "PutKeyPolicy",
            "PutResourcePolicy",
            "ReplicateSecretToRegions",
            "ScheduleKeyDeletion",
            { prefix = "CreateFunction" },
            { prefix = "UpdateFunctionCode" },
            { prefix = "UpdateFunctionConfiguration" },
          ]
        }
      })
    }
  }

  targets = {
    "${var.name}-seal-audit" = [
      {
        name = "${var.name}-seal-audit-logs"
        arn  = module.seal_audit_logs[0].cloudwatch_log_group_arn
      }
    ]
  }
}

resource "aws_cloudwatch_log_resource_policy" "seal_audit" {
  count = local.bootstrap_enabled ? 1 : 0

  policy_name     = "${var.name}-seal-audit"
  policy_document = data.aws_iam_policy_document.seal_audit_delivery.json
}

data "aws_iam_policy_document" "seal_audit_delivery" {
  statement {
    sid     = "EventBridgeDelivery"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com", "events.amazonaws.com"]
    }

    resources = [
      "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/events/${var.name}-seal-audit:*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.aws_account_id]
    }
  }
}

module "seal_audit_metric" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/log-metric-filter"
  version = "~> 5.0"

  count = local.bootstrap_enabled ? 1 : 0

  name           = "${var.name}-seal-audit"
  log_group_name = module.seal_audit_logs[0].cloudwatch_log_group_name
  # The rule already decides what lands here, so every delivered event counts.
  pattern = ""

  metric_transformation_name      = local.seal_audit_metric_name
  metric_transformation_namespace = local.seal_audit_metric_namespace
}

module "seal_audit_alarm" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/metric-alarm"
  version = "~> 5.0"

  count = local.bootstrap_enabled ? 1 : 0

  alarm_name        = "${var.name}-seal-audit"
  alarm_description = "Policy change that could open a read path to a proxy-monster credential"

  namespace   = local.seal_audit_metric_namespace
  metric_name = local.seal_audit_metric_name
  statistic   = "Sum"
  period      = 300

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.seal_audit_alarm_actions
}
