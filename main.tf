data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  aws_account_id = data.aws_caller_identity.current.account_id
  aws_region     = data.aws_region.current.region

  sql_datasources = { for key, ds in var.datasources : key => ds if ds.engine != "athena" }

  bootstrapped = { for key, ds in var.datasources : key => ds if ds.credential_group != null }

  bootstrap_enabled = length(local.bootstrapped) > 0

  # Literal ARNs: references close a cycle, and Principal blocks rot on role recreation.
  bootstrap_role_name = "${var.name}-bootstrap"
  bootstrap_role_arn  = "arn:aws:iam::${local.aws_account_id}:role/${var.name}-bootstrap"
  reader_role_name    = "${var.name}-bootstrap-reader"

  # An external group has no account to assume into, so it reaches neither of the maps below.
  rds_credential_groups = {
    for name, group in var.target_credential_groups : name => group if group.external_host == null
  }
  external_credential_groups = {
    for name, group in var.target_credential_groups : name => group if group.external_host != null
  }

  # One master account per backend instance, not per group: a second group on the same instance reads
  # the same hand-filled secret rather than a copy that drifts the first time the account rotates.
  external_master_secrets = {
    for name, group in local.external_credential_groups : group.external_identifier => group...
  }

  reader_role_arns = {
    for name, group in local.rds_credential_groups :
    name => "arn:aws:iam::${group.aws_account_id}:role/${var.name}-bootstrap-reader"
  }

  proxy_task_exec_role_arns = {
    for key, ds in local.sql_datasources :
    key => "arn:aws:iam::${local.aws_account_id}:role/proxy-${key}-task-exec"
  }

  target_credentials_key_readers = [
    for key, ds in local.bootstrapped : local.proxy_task_exec_role_arns[key]
  ]
  target_credentials_key_users = concat(
    [local.bootstrap_role_arn],
    local.target_credentials_key_readers,
    var.target_credentials_key_admin_role_arns,
  )

  rds_admin_account_ids = {
    for alias, ids in {
      for group in local.rds_credential_groups : group.aws_account_alias => group.aws_account_id...
    } :
    alias => ids[0]
  }
}
