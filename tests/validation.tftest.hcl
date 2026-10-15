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
      listeners = {
        cp-http = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/net/edge/0123456789abcdef/0000000000000001" }
        web     = { arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/net/edge/0123456789abcdef/0000000000000002" }
      }
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
        openssl_image   = "python@sha256:3333333333333333333333333333333333333333333333333333333333333333"
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
      contains(keys(module.ecs.services["proxy-monster-tailscale"].container_definitions), "cert-export"),
      contains(keys(module.ecs.services["proxy-monster-tailscale"].container_definitions), "cert-decrypt"),
    ])
    error_message = "With edge, the tailscale task must run cert-export, cert-decrypt, and caddy."
  }
  assert {
    condition     = keys(aws_vpc_security_group_ingress_rule.edge_nlb_from_tailscale) == ["cp-http", "web"]
    error_message = "The edge NLB must admit the tailscale host on exactly the control-plane and web ports."
  }
  assert {
    condition = contains(
      module.ecs.services["proxy-monster-tailscale"].container_definitions["tailscale"].container_definition.dependsOn,
      { containerName = "caddy", condition = "HEALTHY" },
    )
    error_message = "With edge, the tailscale node must wait for a healthy Caddy before it advertises the Service."
  }
  assert {
    condition     = local.edge_health_checks["cp-http"].path == "/health" && strcontains(local.edge_caddyfile, "path ${join(" ", local.console_control_plane_paths)}") && strcontains(local.edge_caddyfile, "not path ${join(" ", local.console_web_paths)}")
    error_message = "The edge must health-check the control plane on /health and route the same paths as the console ALB."
  }
  assert {
    condition     = length(module.edge_redeploy) == 1
    error_message = "With edge, a schedule must restart the host so a renewed certificate is exported."
  }
}

run "reauth_complete_page_goes_to_web" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition = alltrue([
      module.console_alb.listener_rules["https/web-page"].priority == 90,
      module.console_alb.listener_rules["https/control-plane"].priority > 90,
      one(module.console_alb.listener_rules["https/web-page"].condition).path_pattern[0].values == toset(["/auth/reauth-complete"]),
    ])
    error_message = "The console ALB must send /auth/reauth-complete to web ahead of the /auth/* control-plane rule."
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
        openssl_image   = "python@sha256:3333333333333333333333333333333333333333333333333333333333333333"
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
        openssl_image   = "python@sha256:3333333333333333333333333333333333333333333333333333333333333333"
      }
    }
  }
  expect_failures = [var.tailscale]
}

run "tailscale_edge_certificate_must_be_in_the_module_region" {
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
        certificate_arn = "arn:aws:acm:ap-northeast-2:111111111111:certificate/11111111-1111-1111-1111-111111111111"
        caddy_image     = "caddy@sha256:1111111111111111111111111111111111111111111111111111111111111111"
        cli_image       = "amazon/aws-cli@sha256:2222222222222222222222222222222222222222222222222222222222222222"
        openssl_image   = "python@sha256:3333333333333333333333333333333333333333333333333333333333333333"
      }
    }
  }
  expect_failures = [aws_vpc_security_group_ingress_rule.edge_nlb_from_tailscale]
}

run "tailnet_null_adds_nothing" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition = alltrue([
      length([for e in local.control_plane_environment : e if startswith(e.name, "PM_TAILNET_") || e.name == "PM_WEB_URL"]) == 0,
      !contains(keys(module.internal_nlb.listeners), "web"),
      length(data.aws_acm_certificate.tailnet) == 0,
    ])
    error_message = "A null tailnet must leave the control plane, the internal NLB and the outputs as they were."
  }
}

run "control_plane_task_role_has_a_fixed_name" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition     = module.ecs.services["control-plane"].tasks_iam_role_name == "proxy-monster-control-plane-tasks" && output.control_plane_task_role_arn == "arn:aws:iam::111111111111:role/proxy-monster-control-plane-tasks"
    error_message = "The control-plane task role must keep its fixed name with no tailnet."
  }
}

run "tailnet_serves_the_console_from_the_control_plane" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailnet = {
      client_id    = "example-client-id"
      tag          = "tag:pm-console-host"
      service_name = "svc:pm-console"
    }
  }
  assert {
    condition = alltrue([
      contains(local.control_plane_environment, { name = "AWS_REGION", value = "us-east-1" }),
      contains(local.control_plane_environment, { name = "PM_TAILNET_CLIENT_ID", value = "example-client-id" }),
      contains(local.control_plane_environment, { name = "PM_TAILNET_AUDIENCE", value = "tailscale.workload.identity" }),
      contains(local.control_plane_environment, { name = "PM_TAILNET_TAGS", value = "tag:pm-console-host" }),
      contains(local.control_plane_environment, { name = "PM_TAILNET_SERVICE", value = "svc:pm-console" }),
      data.aws_acm_certificate.tailnet[0].domain == var.console_hostname,
      contains(local.control_plane_environment, { name = "PM_TAILNET_CERT_ARN", value = data.aws_acm_certificate.tailnet[0].arn }),
      contains([for e in local.control_plane_environment : e.name], "PM_WEB_URL"),
    ])
    error_message = "The control plane must log in with client_id, advertise its tag, host the Service with the certificate, and forward web paths to web."
  }
  assert {
    condition = alltrue([
      contains(keys(module.internal_nlb.listeners), "web"),
      local.web_tailnet_load_balancer["nlb-http"].container_name == "web",
      local.web_tailnet_load_balancer["nlb-http"].container_port == 41300,
      module.internal_nlb.target_groups["web"].port == 41300,
    ])
    error_message = "The web service must register on the internal NLB's web listener, which the control plane forwards to."
  }
  assert {
    condition     = module.ecs.services["control-plane"].tasks_iam_role_name == "proxy-monster-control-plane-tasks" && output.control_plane_task_role_arn == "arn:aws:iam::111111111111:role/proxy-monster-control-plane-tasks"
    error_message = "The role ARN must be known at plan time so a caller can trust it before the role exists."
  }
  assert {
    condition     = !contains(keys(module.ecs.services), "proxy-monster-tailscale")
    error_message = "tailnet must not add the tailscale host service."
  }
}

run "tailnet_tag_must_be_a_tag" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailnet = {
      client_id    = "example-client-id"
      tag          = "pm-console-host"
      service_name = "svc:pm-console"
    }
  }
  expect_failures = [var.tailnet]
}

run "tailnet_service_name_must_be_a_dns_label" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    tailnet = {
      client_id    = "example-client-id"
      tag          = "tag:pm-console-host"
      service_name = "pm-console"
    }
  }
  expect_failures = [var.tailnet]
}

run "user_attributes_unset_emits_nothing" {
  command = plan
  variables {
    datasources = { app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } } }
    oidc        = { issuer = "https://idp.example.com", client_id = "pm", group_map = "pm-admins=system:admin" }
  }
  assert {
    condition     = length([for env in module.ecs.services["control-plane"].container_definitions["control-plane"].container_definition.environment : env if env.name == "PM_OIDC_USER_ATTRIBUTES"]) == 0
    error_message = "an unset user_attributes must not emit PM_OIDC_USER_ATTRIBUTES."
  }
}

run "user_attributes_reach_the_control_plane" {
  command = plan
  variables {
    datasources = { app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } } }
    oidc        = { issuer = "https://idp.example.com", client_id = "pm", group_map = "pm-admins=system:admin", user_attributes = "manager:User,teams:Set<String>" }
  }
  assert {
    condition     = contains([for env in module.ecs.services["control-plane"].container_definitions["control-plane"].container_definition.environment : env.value if env.name == "PM_OIDC_USER_ATTRIBUTES"], "manager:User,teams:Set<String>")
    error_message = "user_attributes must reach the control plane as PM_OIDC_USER_ATTRIBUTES."
  }
}

run "unknown_user_attribute_type_is_rejected" {
  command = plan
  variables {
    datasources = { app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } } }
    oidc        = { issuer = "https://idp.example.com", client_id = "pm", group_map = "pm-admins=system:admin", user_attributes = "manager:Email" }
  }
  expect_failures = [var.oidc]
}

run "github_wires_app_and_ci_issuers" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    github          = { app_id = "12345" }
    ci_oidc_issuers = { github = "https://token.actions.githubusercontent.com" }
  }
  assert {
    condition = alltrue([
      contains(local.control_plane_environment, { name = "PM_GITHUB_APP_ID", value = "12345" }),
      contains(local.control_plane_environment, { name = "PM_CI_OIDC_ISSUERS", value = "github=https://token.actions.githubusercontent.com" }),
      length([for e in local.control_plane_environment : e if e.name == "PM_GITHUB_IDENTITY"]) == 0,
      length([for s in local.control_plane_secrets : s if s.name == "PM_GITHUB_APP_PRIVATE_KEY"]) == 1,
      length(aws_secretsmanager_secret.github_app_key) == 1,
    ])
    error_message = "github must set the App ID, the key secret, and the CI issuers; an empty identity keeps the default."
  }
}

run "github_off_adds_nothing" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
  }
  assert {
    condition = alltrue([
      length([for e in local.control_plane_environment : e if startswith(e.name, "PM_GITHUB_") || e.name == "PM_CI_OIDC_ISSUERS"]) == 0,
      length(aws_secretsmanager_secret.github_app_key) == 0,
    ])
    error_message = "Without github or ci_oidc_issuers the control plane gets no GitHub settings."
  }
}

run "ci_oidc_issuer_must_be_https" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    ci_oidc_issuers = { github = "http://token.actions.githubusercontent.com" }
  }
  expect_failures = [var.ci_oidc_issuers]
}

run "disabled_github_and_slack_create_secrets_only" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    github                = { app_id = "12345", enabled = false }
    slack                 = { enabled = false }
    auditmon_slack_alerts = { enabled = false }
  }
  assert {
    condition = alltrue([
      length(aws_secretsmanager_secret.github_app_key) == 1,
      length(aws_secretsmanager_secret.slack) == 1,
      length(aws_secretsmanager_secret.alert_slack_webhook) == 1,
      length([for e in local.control_plane_environment : e if startswith(e.name, "PM_GITHUB_") || startswith(e.name, "PM_NOTIFY_")]) == 0,
      length([for s in local.control_plane_secrets : s if startswith(s.name, "PM_GITHUB_") || startswith(s.name, "PM_SLACK_")]) == 0,
      length(local.control_plane_secret_arns) == 4,
      !strcontains(local.auditmon_config_yaml, "alerts"),
    ])
    error_message = "enabled = false must create each secret and wire none of them."
  }
}

run "disabled_datasource_keeps_its_secret_without_a_proxy" {
  command = plan
  variables {
    datasources = {
      app  = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
      next = { engine = "mysql", wire_port = 40002, credential_group = "app", enabled = false, target = { host = "app.cluster-x.us-east-1.rds.amazonaws.com", port = 3306, db = "app" } }
    }
    bootstrap_client_host_pattern = "10.0.%"
    target_credential_groups = {
      app = {
        aws_account_id = "222222222222", aws_account_alias = "data", rds_kind = "cluster", rds_identifier = "app"
        engine         = "mysql", database = "app", schemas = ["app"]
      }
    }
  }
  assert {
    condition     = contains(keys(aws_secretsmanager_secret.target_credentials), "next")
    error_message = "A disabled datasource must keep its credentials secret."
  }
  assert {
    condition     = contains(keys(module.ecs.services), "proxy-app")
    error_message = "An enabled datasource must keep its proxy."
  }
  assert {
    condition     = !contains(keys(module.ecs.services), "proxy-next")
    error_message = "A disabled datasource must get no proxy service."
  }
  assert {
    condition     = [for k in keys(module.internal_nlb.target_groups) : k if startswith(k, "wire/")] == ["wire/app"]
    error_message = "A disabled datasource must get no NLB wire target group."
  }
  assert {
    condition     = keys(output.wire_endpoints) == ["app"]
    error_message = "A disabled datasource must not appear in wire_endpoints."
  }
  assert {
    condition     = contains(keys(module.target_credentials_key[0].grants), "bootstrap-write-next")
    error_message = "The bootstrap must still be able to fill a disabled datasource's secret."
  }
  assert {
    condition     = !contains(keys(module.target_credentials_key[0].grants), "proxy-read-next")
    error_message = "A disabled datasource must get no proxy read grant."
  }
  assert {
    condition     = length(local.bootstrap_config.groups["app"].serving) == 0
    error_message = "The bootstrap must not restart a disabled datasource's proxy."
  }
  assert {
    condition     = keys(local.bootstrap_config.groups["app"].datasources) == ["next"]
    error_message = "The bootstrap must still fill a disabled datasource's secret."
  }
}

run "omitted_enabled_keeps_slack_and_auditmon_wired" {
  command = plan
  variables {
    datasources = {
      app = { engine = "mysql", wire_port = 40001, target = { host = "db.example.com", port = 3306, db = "app" } }
    }
    slack                 = {}
    auditmon_slack_alerts = {}
  }
  assert {
    condition = alltrue([
      length([for s in local.control_plane_secrets : s if s.name == "PM_SLACK_BOT_TOKEN"]) == 1,
      local.auditmon_slack_enabled,
      strcontains(local.auditmon_config_yaml, "alerts"),
    ])
    error_message = "slack and auditmon_slack_alerts without enabled must stay wired."
  }
}
