output "audit_bucket_id" {
  description = "Name of the auditmon WORM bucket."
  value       = module.audit_bucket.s3_bucket_id
}

output "audit_signer_key_arn" {
  description = "ARN of the auditmon anchor-signing KMS key."
  value       = module.audit_signer_key.key_arn
}

output "aurora_cluster_endpoint" {
  description = "Writer endpoint of the control-plane Aurora PostgreSQL store."
  value       = module.aurora.cluster_endpoint
}

output "bootstrap_function_name" {
  description = "Lambda that provisions the backend DB accounts. Invoke it per group: {\"group\": \"<name>\"}."
  value       = try(module.bootstrap[0].lambda_function_name, null)
}

output "bootstrap_reader_role_name" {
  description = "Reader role name each RDS-owning account creates; the key policies match it as a literal."
  value       = local.reader_role_name
}

output "bootstrap_role_arn" {
  description = "ARN of the bootstrap function's role, to be trusted by the reader role in each RDS-owning account."
  value       = local.bootstrap_role_arn
}

output "aurora_reader_endpoint" {
  description = "Reader endpoint (for the future auditmon read-only DSN)."
  value       = module.aurora.cluster_reader_endpoint
}

output "console_alb_dns_name" {
  description = "Internal ALB DNS name for the web console; CNAME target for the console hostname."
  value       = module.console_alb.dns_name
}

output "console_url" {
  description = "Web console URL served by the internal ALB."
  value       = "https://${var.console_hostname}"
}

output "ecs_cluster_name" {
  description = "Name of the proxy-monster ECS cluster."
  value       = module.ecs.cluster_name
}

output "grpc_endpoint" {
  description = "Control-plane gRPC address (PM_CONTROL_PLANE_GRPC) on the internal NLB."
  value       = "${module.internal_nlb.dns_name}:9090"
}

output "rds_admin_key_arns" {
  description = "KMS key ARN per aws_account_alias, for master_user_secret_kms_key_id on that account's RDS targets."
  value       = { for alias, key in module.rds_admin_key : alias => key.key_arn }
}

output "secret_arns" {
  description = "Secrets Manager ARNs, including the manually-filled shells (oidc-client-secret, target-credentials/*, wire-tls)."
  value = merge(
    {
      grpc-token         = aws_secretsmanager_secret.grpc_token.arn
      oidc-client-secret = aws_secretsmanager_secret.oidc_client_secret.arn
      result-key         = aws_secretsmanager_secret.result_key.arn
      session-secret     = aws_secretsmanager_secret.session_secret.arn
      wire-tls           = aws_secretsmanager_secret.wire_tls.arn
    },
    { for key, secret in aws_secretsmanager_secret.target_credentials : "target-credentials/${key}" => secret.arn },
  )
}

output "target_credentials_key_arn" {
  description = "KMS key ARN guarding the bootstrapped target-credentials secrets."
  value       = try(module.target_credentials_key[0].key_arn, null)
}

# The wire cert is issued by hand, and its SAN has to be the host the proxies advertise — which is the
# NLB's own DNS name, so it is not knowable until the NLB exists. That ordering is the trap: a cert
# minted from a guessed hostname fails pmon's host check at broker time, not at apply time. Emitting the
# commands from the address terraform just computed removes the guess.
output "wire_tls_issuance" {
  description = "Run these after an apply to fill the wire-tls secret. One cert serves every proxy: they share this hostname, and a certificate binds to a host, not a port."
  value = {
    advertise_host = module.internal_nlb.dns_name
    # CN caps at 64 characters and this hostname can exceed it, so the host lives only in the SAN.
    openssl = join(" ", [
      "openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes",
      "-keyout tls.key -out tls.crt",
      "-subj '/CN=${var.name}'",
      "-addext 'subjectAltName=DNS:${module.internal_nlb.dns_name}'",
      "-addext 'keyUsage=critical,digitalSignature,keyEncipherment'",
      "-addext 'extendedKeyUsage=serverAuth'",
    ])
    put_secret = join(" ", [
      "aws secretsmanager put-secret-value",
      "--secret-id ${aws_secretsmanager_secret.wire_tls.name}",
      "--secret-string \"$(jq -n --arg c \"$(cat tls.crt)\" --arg k \"$(cat tls.key)\" '{cert: $c, key: $k}')\"",
    ])
  }
}

output "wire_endpoints" {
  description = "SQL-wire endpoint per datasource (point pmon --proxy here)."
  value       = { for key, ds in var.datasources : key => "${module.internal_nlb.dns_name}:${ds.wire_port}" }
}
