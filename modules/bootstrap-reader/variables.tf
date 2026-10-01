variable "bootstrap_account_id" {
  type        = string
  description = "Account the proxy-monster bootstrap function runs in."
}

variable "bootstrap_role_arn" {
  type        = string
  description = "ARN of the bootstrap function's role; the only principal this role trusts."
}

variable "rds_admin_key_arn" {
  type        = string
  description = "The rds-admin KMS key for this account; also what master_user_secret_kms_key_id must be set to."
}

variable "rds_arns" {
  type        = list(string)
  description = "RDS cluster and instance ARNs this role may describe."
}

variable "role_name" {
  type        = string
  description = "Role name; the rds-admin key policy matches it as a literal."
  default     = "proxy-monster-bootstrap-reader"
}
