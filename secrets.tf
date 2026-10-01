# Generated secrets: ephemeral values + write-only versions (never in state). result-key
# has its own version because PM_RESULT_KEY encrypts data at rest, so rotating it orphans
# existing ciphertext. ECS reads secrets at boot, so bumping any version needs a
# force-new-deployment (control-plane + all proxies together for the grpc-token).
ephemeral "random_password" "session_secret" {
  length  = 48
  special = false
}

ephemeral "random_password" "result_key" {
  length  = 32
  special = false
}

ephemeral "random_password" "grpc_token" {
  length  = 64
  special = false
}

ephemeral "random_password" "db_master" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "session_secret" {
  name                    = "${var.name}/session-secret"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "session_secret" {
  secret_id                = aws_secretsmanager_secret.session_secret.id
  secret_string_wo         = ephemeral.random_password.session_secret.result
  secret_string_wo_version = var.secret_rotation_version
}

resource "aws_secretsmanager_secret" "result_key" {
  name                    = "${var.name}/result-key"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "result_key" {
  secret_id = aws_secretsmanager_secret.result_key.id
  # PM_RESULT_KEY must be base64 that decodes to exactly 32 bytes (AES-256).
  secret_string_wo         = base64encode(ephemeral.random_password.result_key.result)
  secret_string_wo_version = var.result_key_version
}

resource "aws_secretsmanager_secret" "grpc_token" {
  name                    = "${var.name}/grpc-token"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "grpc_token" {
  secret_id                = aws_secretsmanager_secret.grpc_token.id
  secret_string_wo         = ephemeral.random_password.grpc_token.result
  secret_string_wo_version = var.secret_rotation_version
}

# Self-managed Aurora master password (aurora.tf), read by control-plane as PM_DB_PASSWORD.
resource "aws_secretsmanager_secret" "db_master" {
  name                    = "${var.name}/db-master-password"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id                = aws_secretsmanager_secret.db_master.id
  secret_string_wo         = ephemeral.random_password.db_master.result
  secret_string_wo_version = var.db_master_password_version
}

# Wire TLS: a JSON {"cert","key"} of the leaf PEM every proxy serves on its wire port.
# Self-signed is the intended shape — the proxy registers this chain with the control plane, which hands
# it to pmon as the trust root and checks the advertised host against it, so no CA is involved and there
# is none to rotate. Generated and filled by hand, so no version is created here.
#
# One secret, not one per datasource: every proxy is reached at the same internal NLB hostname and a
# certificate binds to a hostname, not a port, so a per-proxy secret could only ever hold identical
# bytes — while multiplying the by-hand generation and the rotation surface.
resource "aws_secretsmanager_secret" "wire_tls" {
  name                    = "${var.name}/wire-tls"
  recovery_window_in_days = var.secret_recovery_window_days
}

# Shells only — values are filled manually (no version is created here).
# Dependent tasks (control-plane SSO / wire proxies) fail to start until filled.
resource "aws_secretsmanager_secret" "oidc_client_secret" {
  name                    = "${var.name}/oidc-client-secret"
  recovery_window_in_days = var.secret_recovery_window_days
}

# Slack approval notifications (control-plane): a JSON {"bot_token":"xoxb-…","app_token":"xapp-…"} for the
# Socket Mode app, created only where a caller enables var.slack. Shell only — the value is filled
# out-of-band (no version here, like alert_slack_webhook below), so the tokens never enter terraform state;
# the control-plane task fails to start until the value is filled.
resource "aws_secretsmanager_secret" "slack" {
  for_each = var.slack == null ? {} : { this = var.slack }

  name                    = "${var.name}/slack"
  recovery_window_in_days = var.secret_recovery_window_days
}

# auditmon's Slack webhook URL, created only where a caller enables auditmon_slack_alerts. Shell only —
# the value is filled out-of-band (no version here), so it never enters terraform state; like the
# hand-filled secrets above, a dependent task fails to start until the value is filled.
resource "aws_secretsmanager_secret" "alert_slack_webhook" {
  count                   = var.auditmon_slack_alerts == null ? 0 : 1
  name                    = "${var.name}/alert-slack-webhook"
  recovery_window_in_days = var.secret_recovery_window_days
}

# Bootstrapped datasources are filled by the function on the CMK; the rest are hand-filled shells.
resource "aws_secretsmanager_secret" "target_credentials" {
  for_each = var.datasources

  name                    = "${var.name}/target-credentials/${each.key}"
  recovery_window_in_days = var.secret_recovery_window_days
  kms_key_id = (
    each.value.credential_group == null ? null : module.target_credentials_key[0].key_arn
  )
}

# Shell only, like the hand-filled secrets above. On the default key rather than the
# target-credentials CMK, which denies read to everyone a human might type this in as.
resource "aws_secretsmanager_secret" "master_credentials" {
  for_each = local.external_master_secrets

  name                    = "${var.name}/master-credentials/${each.key}"
  recovery_window_in_days = var.secret_recovery_window_days
  description             = "Master DB account on the ${each.key} target, filled by hand. JSON: {\"username\": \"...\", \"password\": \"...\"}. The bootstrap function reads this to create ${join(", ", sort([for group in each.value : group.username]))} on ${each.value[0].external_host}."
}

# The default key admits any same-account SecretsManagerReadWrite holder, and this value outranks
# the broker credential it mints: it can create roles on the backend. Reads are therefore denied to
# everyone but the function, while writes stay open so an operator can still fill it in the console.
resource "aws_secretsmanager_secret_policy" "master_credentials" {
  for_each = local.external_master_secrets

  secret_arn          = aws_secretsmanager_secret.master_credentials[each.key].arn
  policy              = data.aws_iam_policy_document.master_credentials[each.key].json
  block_public_policy = true
}

data "aws_iam_policy_document" "master_credentials" {
  for_each = local.external_master_secrets

  statement {
    sid     = "AllowRead"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.aws_account_id}:root"]
    }

    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.bootstrap_role_arn]
    }
  }

  statement {
    sid     = "DenyRead"
    effect  = "Deny"
    actions = ["secretsmanager:GetSecretValue"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = ["*"]

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values = concat(
        [local.bootstrap_role_arn],
        var.target_credentials_key_admin_role_arns,
      )
    }
  }
}

# Second layer over the KMS policy, so opening a read path takes two policy edits rather than one.
resource "aws_secretsmanager_secret_policy" "target_credentials" {
  for_each = local.bootstrapped

  secret_arn          = aws_secretsmanager_secret.target_credentials[each.key].arn
  policy              = data.aws_iam_policy_document.target_credentials[each.key].json
  block_public_policy = true

  # Nothing else orders the literal-ARN policy against the exec-role rename.
  depends_on = [module.ecs]
}

data "aws_iam_policy_document" "target_credentials" {
  for_each = local.bootstrapped

  statement {
    sid     = "AllowRead"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.aws_account_id}:root"]
    }

    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.proxy_task_exec_role_arns[each.key]]
    }
  }

  statement {
    sid     = "DenyRead"
    effect  = "Deny"
    actions = ["secretsmanager:GetSecretValue"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = ["*"]

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.proxy_task_exec_role_arns[each.key], local.bootstrap_role_arn]
    }
  }
}
