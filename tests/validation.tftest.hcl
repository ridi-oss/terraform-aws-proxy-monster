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

run "tailscale_null_adds_no_host" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition     = !contains(keys(module.ecs.services), "proxy-monster-tailscale") && output.tailscale_task_role_arn == null
    error_message = "A null tailscale must add no service and no role."
  }
}

run "tailscale_host_advertises_the_service" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
  assert {
    condition = alltrue([
      contains(module.ecs.services["proxy-monster-tailscale"].container_definitions["tailscale"].container_definition.environment, { name = "TS_CLIENT_ID", value = "example-client-id" }),
      contains(module.ecs.services["proxy-monster-tailscale"].container_definitions["tailscale"].container_definition.environment, { name = "TS_EXTRA_ARGS", value = "--advertise-tags=tag:pm-console-host" }),
      contains(module.ecs.services["proxy-monster-tailscale"].container_definitions["tailscale"].container_definition.environment, { name = "TS_SERVE_CONFIG", value = "/data/ts/serve.json" }),
    ])
    error_message = "The tailscale host must authenticate with client_id, advertise its tag, and read the serve config."
  }
  assert {
    condition     = output.tailscale_task_role_arn == "arn:aws:iam::111111111111:role/proxy-monster-tailscale-tasks"
    error_message = "The role ARN must be known at plan time so a caller can trust it before the role exists."
  }
}

run "tailscale_tag_only_image_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale:stable"
    }
  }
  expect_failures = [var.tailscale]
}

run "tailscale_service_name_must_be_a_dns_label" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:PM_Console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
  expect_failures = [var.tailscale]
}

run "tailscale_empty_client_id_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = " "
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
  expect_failures = [var.tailscale]
}

run "tailscale_serve_config_forwards_80_and_443_to_the_alb" {
  command = plan
  override_module {
    target = module.console_alb
    outputs = {
      dns_name          = "internal-console.example.com"
      security_group_id = "sg-0123456789abcdef0"
      target_groups = {
        control-plane = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/cp/0123456789abcdef" }
        web           = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/web/0123456789abcdef" }
      }
    }
  }
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
  assert {
    condition = jsondecode(one([
      for e in module.ecs.services["proxy-monster-tailscale"].container_definitions["config-init"].container_definition.environment : e.value if e.name == "TS_SERVE_CONFIG_JSON"
      ])).Services["svc:pm-console"].TCP == {
      "80"  = { TCPForward = "internal-console.example.com:80" }
      "443" = { TCPForward = "internal-console.example.com:443" }
    }
    error_message = "The serve config must forward the Service's 80 and 443 to the console ALB."
  }
}

run "tailscale_edge_forwards_with_proxy_protocol_to_caddy" {
  command = plan
  override_module {
    target = module.edge_nlb
    outputs = {
      dns_name          = "internal-edge.example.com"
      security_group_id = "sg-0fedcba9876543210"
      target_groups = {
        cp-http = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/edge-cp/0123456789abcdef" }
        web     = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/edge-web/0123456789abcdef" }
      }
    }
  }
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      edge = {
        certificate_arn = "arn:aws:acm:us-east-1:111111111111:certificate/11111111-1111-1111-1111-111111111111"
        caddy_image     = "caddy@sha256:1111111111111111111111111111111111111111111111111111111111111111"
        cli_image       = "amazon/aws-cli@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      }
    }
  }
  assert {
    condition = jsondecode(one([
      for e in module.ecs.services["proxy-monster-tailscale"].container_definitions["config-init"].container_definition.environment : e.value if e.name == "TS_SERVE_CONFIG_JSON"
      ])).Services["svc:pm-console"].TCP == {
      "80"  = { TCPForward = "127.0.0.1:8880", ProxyProtocol = 2 }
      "443" = { TCPForward = "127.0.0.1:8443", ProxyProtocol = 2 }
    }
    error_message = "With edge, the serve config must hand 80 and 443 to the local Caddy with a PROXY v2 header."
  }
  assert {
    condition = alltrue([
      for line in [
        "reverse_proxy @control_plane internal-edge.example.com:8080",
        "reverse_proxy internal-edge.example.com:41300",
        "allow 127.0.0.1/32",
      ] : strcontains(local.edge_caddyfile, line)
    ]) && !strcontains(local.edge_caddyfile, "console")
    error_message = "Caddy must accept PROXY headers only from localhost and reach both upstreams through the edge NLB, never the console ALB."
  }
  assert {
    condition = alltrue([
      contains(keys(module.ecs.services["proxy-monster-tailscale"].container_definitions), "caddy"),
      contains(keys(module.ecs.services["proxy-monster-tailscale"].container_definitions), "cert-init"),
    ])
    error_message = "With edge, the tailscale task must run cert-init and caddy."
  }
  assert {
    condition     = keys(aws_vpc_security_group_ingress_rule.edge_nlb_from_tailscale) == ["cp-http", "web"]
    error_message = "The edge NLB must admit the tailscale host on exactly the control-plane and web ports."
  }
  assert {
    condition     = length(module.edge_redeploy) == 1
    error_message = "With edge, a schedule must restart the host so a renewed certificate is exported."
  }
}

run "tailscale_without_edge_adds_no_edge_resources" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
  assert {
    condition = alltrue([
      length(module.edge_nlb) == 0,
      length(module.edge_redeploy) == 0,
      length(aws_vpc_security_group_ingress_rule.edge_nlb_from_tailscale) == 0,
      !contains(keys(module.ecs.services["proxy-monster-tailscale"].container_definitions), "caddy"),
    ])
    error_message = "A tailscale host without edge must add no edge NLB, schedule, rule, or Caddy."
  }
}

run "tailscale_edge_tag_only_image_is_rejected" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      edge = {
        certificate_arn = "arn:aws:acm:us-east-1:111111111111:certificate/11111111-1111-1111-1111-111111111111"
        caddy_image     = "caddy:2"
        cli_image       = "amazon/aws-cli@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      }
    }
  }
  expect_failures = [var.tailscale]
}

run "tailscale_edge_certificate_must_be_acm" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailscale = {
      service_name = "svc:pm-console"
      tag          = "tag:pm-console-host"
      client_id    = "example-client-id"
      image        = "tailscale/tailscale@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      edge = {
        certificate_arn = "arn:aws:iam::111111111111:server-certificate/console"
        caddy_image     = "caddy@sha256:1111111111111111111111111111111111111111111111111111111111111111"
        cli_image       = "amazon/aws-cli@sha256:2222222222222222222222222222222222222222222222222222222222222222"
      }
    }
  }
  expect_failures = [var.tailscale]
}
