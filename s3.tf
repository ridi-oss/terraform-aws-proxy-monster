# auditmon WORM export trail. The GOVERNANCE default keeps a dev bucket deletable; a stack that
# brokers production data sets audit_lock_mode = COMPLIANCE, under which no principal (root
# included) can shorten or remove a lock before it expires.
module "audit_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.7"

  bucket = var.audit_bucket_name

  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = var.audit_lock_mode
        days = var.audit_retention_days
      }
    }
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  attach_deny_insecure_transport_policy = true

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
      bucket_key_enabled = true
    }
  }
}
