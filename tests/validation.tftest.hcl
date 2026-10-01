mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = { cidr_block = "10.0.0.0/20", availability_zone = "us-east-1a" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_data "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_data "aws_iam_policy" {
    defaults = { policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
}
mock_provider "archive" {}
mock_provider "external" {
  mock_data "external" {
    defaults = { result = { payload_dir = "bootstrap" } }
  }
}
mock_provider "http" {
  mock_data "http" {
    defaults = { status_code = 200, response_body = "-----BEGIN CERTIFICATE-----" }
  }
}

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

run "postgres_group_needs_no_host_pattern" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 5432, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "postgres", database = "app", schemas = ["public"]
      }
    }
  }
}

run "mysql_group_needs_host_pattern" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 3306, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "mysql", database = "app", schemas = ["app"]
      }
    }
  }
  expect_failures = [var.bootstrap_client_host_pattern]
}

run "postgres_role_create_needs_postgres_role" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 5432, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "postgres", database = "app", schemas = ["app"], postgres_role_create = true
      }
    }
  }
  expect_failures = [var.target_credential_groups]
}

run "postgres_role_create_rejects_repeated_schema" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 5432, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "postgres", database = "app", schemas = ["app", "app"], postgres_role = "app_owner", postgres_role_create = true
      }
    }
  }
  expect_failures = [var.target_credential_groups]
}

run "database_privileges_need_postgres_role_create" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 5432, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "postgres", database = "app", schemas = ["app"], postgres_role = "app_owner", postgres_role_database_privileges = ["CREATE"]
      }
    }
  }
  expect_failures = [var.target_credential_groups]
}

run "unknown_database_privilege_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "postgres", wire_port = 40001, credential_group = "app", target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 5432, db = "app" } }
    }
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "postgres", database = "app", schemas = ["app"], postgres_role = "app_owner", postgres_role_create = true, postgres_role_database_privileges = ["ALL"]
      }
    }
  }
  expect_failures = [var.target_credential_groups]
}
run "athena_datasource_has_no_target_secret" {
  command = plan
  variables {
    datasources = {
      dw = {
        engine    = "athena"
        wire_port = 40002
        athena    = { workgroup = "primary", database = "logs", result_prefix = "results-bucket/athena/", data_prefixes = ["data-bucket/warehouse/"] }
      }
    }
  }
  assert {
    condition     = !contains(keys(aws_secretsmanager_secret.target_credentials), "dw")
    error_message = "An athena datasource must get no target-credentials secret."
  }
  assert {
    condition = alltrue([
      contains(module.ecs.services["proxy-dw"].container_definitions["proxy"].container_definition.environment, { name = "PM_ATHENA_WORKGROUP", value = "primary" }),
      contains(module.ecs.services["proxy-dw"].container_definitions["proxy"].container_definition.environment, { name = "PM_TARGET_DB", value = "logs" }),
    ])
    error_message = "An athena proxy must receive its workgroup and database."
  }
}

run "athena_bucket_without_slash_is_rejected" {
  command = plan
  variables {
    datasources = {
      dw = {
        engine    = "athena"
        wire_port = 40002
        athena    = { workgroup = "primary", database = "logs", result_prefix = "results-bucket", data_prefixes = ["data-bucket/warehouse/"] }
      }
    }
  }
  expect_failures = [var.datasources]
}

run "athena_wildcard_prefix_is_rejected" {
  command = plan
  variables {
    datasources = {
      dw = {
        engine    = "athena"
        wire_port = 40002
        athena    = { workgroup = "primary", database = "logs", result_prefix = "results-bucket/athena/", data_prefixes = ["data-bucket/*/"] }
      }
    }
  }
  expect_failures = [var.datasources]
}

run "athena_without_data_prefixes_is_rejected" {
  command = plan
  variables {
    datasources = {
      dw = {
        engine    = "athena"
        wire_port = 40002
        athena    = { workgroup = "primary", database = "logs", result_prefix = "results-bucket/athena/", data_prefixes = [] }
      }
    }
  }
  expect_failures = [var.datasources]
}

run "athena_other_catalog_is_rejected" {
  command = plan
  variables {
    datasources = {
      dw = {
        engine    = "athena"
        wire_port = 40002
        athena    = { workgroup = "primary", database = "logs", catalog = "federated", result_prefix = "results-bucket/athena/", data_prefixes = ["data-bucket/warehouse/"] }
      }
    }
  }
  expect_failures = [var.datasources]
}

run "description_with_tab_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, description = "orders\tdb", target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  expect_failures = [var.datasources]
}
