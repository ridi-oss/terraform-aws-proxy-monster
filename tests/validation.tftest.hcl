mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = { cidr_block = "10.0.0.0/20", availability_zone = "us-east-1a" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_data "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
}
mock_provider "archive" {}
mock_provider "external" {}
mock_provider "http" {}

variables {
  vpc_id            = "vpc-0123456789abcdef0"
  vpc_cidr          = "10.0.0.0/16"
  private_subnets   = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"]
  database_subnets  = ["subnet-0bbbbbbbbbbbbbbb1", "subnet-0bbbbbbbbbbbbbbb2"]
  console_hostname  = "pm.example.com"
  audit_bucket_name = "example-proxy-monster-audit"
  images = {
    control_plane = "example/pm-control-plane:0"
    proxy         = "example/pm-goproxy:0"
    web           = "example/pm-web:0"
    auditmon      = "example/pm-auditmon:0"
  }
}

run "tls_defaults_to_disable" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition     = length([for env in module.ecs.services["proxy-app"].container_definitions["proxy"].container_definition.environment : env if startswith(env.name, "PM_TARGET_TLS") || env.name == "PM_TARGET_CA"]) == 0
    error_message = "disable must emit neither PM_TARGET_TLS nor PM_TARGET_CA."
  }
}

run "verify_full_with_ca" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, target = { host = "db.example.com", port = 5432, db = "app", tls = "verify-full", ca = "rds" } }
    }
  }
  assert {
    condition = alltrue([
      contains(module.ecs.services["proxy-app"].container_definitions["proxy"].container_definition.environment, { name = "PM_TARGET_TLS", value = "verify-full" }),
      contains(module.ecs.services["proxy-app"].container_definitions["proxy"].container_definition.environment, { name = "PM_TARGET_CA", value = "rds" }),
    ])
    error_message = "verify-full with a CA must reach the proxy as PM_TARGET_TLS and PM_TARGET_CA."
  }
}

run "verify_ca_without_ca_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, target = { host = "db.example.com", port = 5432, db = "app", tls = "verify-ca" } }
    }
  }
  expect_failures = [var.datasources]
}

run "verify_ca_trusting_rds_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, target = { host = "db.example.com", port = 5432, db = "app", tls = "verify-ca", ca = "rds" } }
    }
  }
  expect_failures = [var.datasources]
}

run "unknown_tls_mode_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app", tls = "prefer" } }
    }
  }
  expect_failures = [var.datasources]
}

run "ca_without_verification_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app", tls = "require", ca = "rds" } }
    }
  }
  expect_failures = [var.datasources]
}
