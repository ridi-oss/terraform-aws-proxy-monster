# Resolved from the subnet IDs the module already takes, rather than a second CIDR variable a
# caller could let drift out of step with private_subnets.
data "aws_subnet" "private" {
  for_each = toset(var.private_subnets)
  id       = each.value
}

locals {
  control_plane_environment = concat(
    [
      { name = "PM_HTTP_PORT", value = "8080" },
      { name = "PM_GRPC_PORT", value = "9090" },
      { name = "PM_DB_URL", value = "jdbc:postgresql://${module.aurora.cluster_endpoint}:${module.aurora.cluster_port}/proxymonster" },
      { name = "PM_DB_USER", value = local.db_master_username },
      { name = "PM_MCP_RESOURCE", value = "https://${var.console_hostname}/mcp" },
      # The console ALB is the edge whose X-Forwarded-* may be believed, and it sits in
      # var.private_subnets (alb.tf), so its ENIs must be in this set. Unset, every audit row
      # records the load balancer as the requester_ip instead of the client, and any policy
      # conditioning on it fails closed.
      #
      # This trusts the private subnets, which is WIDER than the ALB: the web and proxy tasks
      # share them, so a compromised in-VPC task could forge X-Forwarded-For and misattribute
      # an audit row. An ENI-only trust set is not expressible here (the addresses are dynamic
      # and would churn every deployment), so this is a deliberate trade: narrower than the
      # VPC, wider than the edge. Tightening it needs the app to accept a resolvable name or
      # the ALB to get static ENIs.
      { name = "PM_TRUSTED_PROXIES", value = join(",", sort([for s in data.aws_subnet.private : s.cidr_block])) },
    ],
    var.instance.name == null ? [] : [{ name = "PM_INSTANCE_NAME", value = var.instance.name }],
    var.instance.description == "" ? [] : [{ name = "PM_INSTANCE_DESCRIPTION", value = var.instance.description }],
    var.oidc == null ? [
      # No IdP yet: run auth-disabled. PM_AUTH_DEBUG alone trips the app's
      # "production-looking" guard (PM_SESSION_SECRET is set), so PM_DEV opts in.
      { name = "PM_AUTH_DEBUG", value = "true" },
      { name = "PM_DEV", value = "true" },
      ] : [
      { name = "PM_AUTH_DEBUG", value = "false" },
      { name = "PM_OIDC_ISSUER", value = var.oidc.issuer },
      { name = "PM_OIDC_CLIENT_ID", value = var.oidc.client_id },
      { name = "PM_OIDC_REDIRECT_URI", value = "https://${var.console_hostname}/auth/oidc/callback" },
      # Required for SSO to grant anything: see the group_map note on var.oidc. Passthrough
      # (this unset) filters `system:*`, so an admin signs in and resolves to zero roles.
      { name = "PM_OIDC_GROUP_MAP", value = var.oidc.group_map },
    ],
    var.slack == null ? [] : [
      { name = "PM_NOTIFY_STATEMENT", value = var.slack.statement },
      { name = "PM_NOTIFY_LOCALE", value = var.slack.locale },
    ],
  )

  control_plane_secrets = concat(
    [
      { name = "PM_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.db_master.arn },
      { name = "PM_SESSION_SECRET", valueFrom = aws_secretsmanager_secret.session_secret.arn },
      { name = "PM_RESULT_KEY", valueFrom = aws_secretsmanager_secret.result_key.arn },
      { name = "PM_SECRET_TOKEN", valueFrom = aws_secretsmanager_secret.grpc_token.arn },
    ],
    var.oidc == null ? [] : [
      { name = "PM_OIDC_CLIENT_SECRET", valueFrom = aws_secretsmanager_secret.oidc_client_secret.arn },
    ],
    var.slack == null ? [] : [
      { name = "PM_SLACK_BOT_TOKEN", valueFrom = "${one(values(aws_secretsmanager_secret.slack)[*].arn)}:bot_token::" },
      { name = "PM_SLACK_APP_TOKEN", valueFrom = "${one(values(aws_secretsmanager_secret.slack)[*].arn)}:app_token::" },
    ],
  )

  control_plane_secret_arns = concat(
    [
      aws_secretsmanager_secret.session_secret.arn,
      aws_secretsmanager_secret.result_key.arn,
      aws_secretsmanager_secret.grpc_token.arn,
      aws_secretsmanager_secret.db_master.arn,
    ],
    var.oidc == null ? [] : [aws_secretsmanager_secret.oidc_client_secret.arn],
    var.slack == null ? [] : [one(values(aws_secretsmanager_secret.slack)[*].arn)],
  )

  auditmon_slack_enabled = var.auditmon_slack_alerts != null

  # auditmon runs env-only on a missing config file, so a split between config-init's write path and
  # the monitor's read path (AUDITMON_CONFIG) would silently drop the rules and sink instead of failing.
  auditmon_config_path = "/etc/auditmon/auditmon.yaml"

  # The rules run on every stack — audit checks are independent of Slack — so they are always mounted;
  # the alerts sink is added only where a caller opts into Slack (var.auditmon_slack_alerts).
  auditmon_config_yaml = yamlencode(merge(
    {
      rules = {
        mass_export = {
          window                    = "10m"
          heuristic_max_broad_reads = 20
          default                   = { rows = 10000, bytes = 104857600 }
        }
        bulk_pii = {
          window                   = "5m"
          max_pii_decisions        = 50
          max_distinct_pii_columns = 10
        }
        off_hours = {
          business_hours = "08:00-20:00 Asia/Seoul"
          applies_to     = ["pii_read", "write"]
        }
        repeated_deny = {
          window   = "5m"
          max_deny = 5
        }
      }
    },
    local.auditmon_slack_enabled ? {
      alerts = {
        dedup_window = "15m"
        console_url  = "https://${var.console_hostname}"
        sinks = [{
          type         = "webhook"
          format       = "slack"
          url_env      = "SLACK_WEBHOOK_URL"
          min_severity = try(var.auditmon_slack_alerts.min_severity, "warn")
          rules        = ["*"]
        }]
      }
    } : {},
  ))
}

locals {
  tailscale_service           = "${var.name}-tailscale"
  tailscale_audience          = "tailscale.workload.identity"
  tailscale_tasks_role_name   = "${var.name}-tailscale-tasks"
  tailscale_tasks_role_arn    = "arn:aws:iam::${local.aws_account_id}:role/${local.tailscale_tasks_role_name}"
  tailscale_serve_config_path = "/data/ts/serve.json"
  tailscale_serve_config = var.tailscale == null ? "" : local.edge_enabled ? jsonencode({
    Services = {
      (var.tailscale.service_name) = {
        TCP = {
          "80"  = { TCPForward = "127.0.0.1:${local.edge_http_port}", ProxyProtocol = 2 }
          "443" = { TCPForward = "127.0.0.1:${local.edge_https_port}", ProxyProtocol = 2 }
        }
      }
    }
    }) : jsonencode({
    Services = {
      (var.tailscale.service_name) = {
        TCP = {
          "80"  = { TCPForward = "${module.console_alb.dns_name}:80" }
          "443" = { TCPForward = "${module.console_alb.dns_name}:443" }
        }
      }
    }
  })
}

module "ecs" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "~> 7.5"

  cluster_name = var.name

  cluster_setting = [
    {
      name  = "containerInsights"
      value = "enabled"
    }
  ]

  cluster_capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy = {
    FARGATE = {
      weight = 100
      base   = 1
    }
  }

  services = merge(
    {
      control-plane = {
        cpu    = var.control_plane_task_size.cpu
        memory = var.control_plane_task_size.memory

        container_definitions = {
          control-plane = {
            essential = true
            # Explicit so the drain budget is reviewable, not an upstream module default. Covers the
            # control-plane's bounded shutdown (a few seconds) before SIGKILL.
            stop_timeout = 30
            image        = var.images.control_plane

            portMappings = [
              {
                name          = "http"
                containerPort = 8080
                protocol      = "tcp"
              },
              {
                name          = "grpc"
                containerPort = 9090
                protocol      = "tcp"
              },
            ]

            environment = local.control_plane_environment
            secrets     = local.control_plane_secrets

            # Cedar extracts its native lib to the image's writable /tmp (1777) at boot;
            # the module's default read-only root fs blocks that. A mounted scratch volume
            # would shadow /tmp as root-owned 0755, so relax the root fs instead.
            readonlyRootFilesystem = false

            enable_cloudwatch_logging = true
          }
        }

        subnet_ids = var.private_subnets

        task_exec_secret_arns = local.control_plane_secret_arns

        security_group_ingress_rules = merge(
          {
            alb-http = {
              from_port                    = 8080
              to_port                      = 8080
              ip_protocol                  = "tcp"
              referenced_security_group_id = module.console_alb.security_group_id
            }
            nlb-http = {
              from_port                    = 8080
              to_port                      = 8080
              ip_protocol                  = "tcp"
              referenced_security_group_id = module.internal_nlb.security_group_id
            }
            nlb-grpc = {
              from_port                    = 9090
              to_port                      = 9090
              ip_protocol                  = "tcp"
              referenced_security_group_id = module.internal_nlb.security_group_id
            }
          },
          { for key, value in {
            edge-http = {
              from_port                    = 8080
              to_port                      = 8080
              ip_protocol                  = "tcp"
              referenced_security_group_id = try(module.edge_nlb[0].security_group_id, null)
            }
          } : key => value if local.edge_enabled },
        )
        security_group_egress_rules = {
          all = {
            ip_protocol = "-1"
            cidr_ipv4   = "0.0.0.0/0"
            description = "Aurora, Secrets Manager, ECR, OIDC IdP"
          }
        }

        desired_count      = 1
        enable_autoscaling = false

        requires_compatibilities = ["FARGATE"]
        launch_type              = "FARGATE"
        runtime_platform = {
          cpu_architecture        = "ARM64"
          operating_system_family = "LINUX"
        }

        # Flyway migrates the store on first boot before /health responds.
        health_check_grace_period_seconds = 120

        load_balancer = merge(
          {
            alb-http = {
              target_group_arn = module.console_alb.target_groups["control-plane"].arn
              container_name   = "control-plane"
              container_port   = 8080
            }
            nlb-http = {
              target_group_arn = module.internal_nlb.target_groups["cp-http"].arn
              container_name   = "control-plane"
              container_port   = 8080
            }
            nlb-grpc = {
              target_group_arn = module.internal_nlb.target_groups["cp-grpc"].arn
              container_name   = "control-plane"
              container_port   = 9090
            }
          },
          { for key, value in {
            edge-http = {
              target_group_arn = try(local.edge_target_group_arns_after_listeners["cp-http"], null)
              container_name   = "control-plane"
              container_port   = 8080
            }
          } : key => value if local.edge_enabled },
        )
      }

      web = {
        cpu    = 512
        memory = 1024

        container_definitions = {
          web = {
            essential = true
            image     = var.images.web

            portMappings = [
              {
                name          = "http"
                containerPort = 41300
                protocol      = "tcp"
              },
            ]

            environment = [
              { name = "PM_PROXY_TARGET", value = "http://${module.internal_nlb.dns_name}:8080" },
            ]

            enable_cloudwatch_logging = true
          }
        }

        subnet_ids = var.private_subnets

        security_group_ingress_rules = merge(
          {
            alb-http = {
              from_port                    = 41300
              to_port                      = 41300
              ip_protocol                  = "tcp"
              referenced_security_group_id = module.console_alb.security_group_id
            }
          },
          { for key, value in {
            edge-http = {
              from_port                    = 41300
              to_port                      = 41300
              ip_protocol                  = "tcp"
              referenced_security_group_id = try(module.edge_nlb[0].security_group_id, null)
            }
          } : key => value if local.edge_enabled },
        )
        security_group_egress_rules = {
          all = {
            ip_protocol = "-1"
            cidr_ipv4   = "0.0.0.0/0"
            description = "Control plane via NLB, ECR"
          }
        }

        desired_count      = 1
        enable_autoscaling = false

        requires_compatibilities = ["FARGATE"]
        launch_type              = "FARGATE"
        runtime_platform = {
          cpu_architecture        = "ARM64"
          operating_system_family = "LINUX"
        }

        health_check_grace_period_seconds = 60

        load_balancer = merge(
          {
            alb-http = {
              target_group_arn = module.console_alb.target_groups["web"].arn
              container_name   = "web"
              container_port   = 41300
            }
          },
          { for key, value in {
            edge-http = {
              target_group_arn = try(local.edge_target_group_arns_after_listeners["web"], null)
              container_name   = "web"
              container_port   = 41300
            }
          } : key => value if local.edge_enabled },
        )
      }
    },
    {
      for key, ds in var.datasources : "proxy-${key}" => {
        cpu    = 512
        memory = 1024

        volume = {
          wire-tls = {}
        }

        container_definitions = {
          # The proxy reads its cert and key as FILES (it watches the paths to reload) while ECS injects
          # secrets as environment variables. This writes them onto a volume both containers share, then
          # exits; the proxy does not start until it has (dependsOn SUCCESS).
          tls-init = {
            essential  = false
            image      = "public.ecr.aws/docker/library/busybox:1.37"
            user       = "0"
            entrypoint = ["/bin/sh", "-c"]
            command = [join(" ", [
              "set -eu;",
              # The shell is created empty and filled by hand, so an unfilled secret is the expected
              # first state. Refuse it here: writing empty files instead makes the proxy fail to parse
              # a certificate, which reads as a code fault rather than an unfilled secret.
              "test -n \"$WIRE_TLS_CERT\" || { echo 'wire-tls secret carries no cert' >&2; exit 1; };",
              "test -n \"$WIRE_TLS_KEY\" || { echo 'wire-tls secret carries no key' >&2; exit 1; };",
              "printf %s \"$WIRE_TLS_CERT\" > /tls/tls.crt;",
              "printf %s \"$WIRE_TLS_KEY\"  > /tls/tls.key;",
              # The key is group-readable only, so proxy_runtime_gid must be the gid the proxy image
              # runs as. Nothing here can check that — this container does not have the proxy image —
              # and a mismatch surfaces as the proxy crashing on a permission-denied key read. The
              # variable exists so the coupling is declared rather than buried in a literal.
              "chmod 0644 /tls/tls.crt; chmod 0640 /tls/tls.key;",
              "chown 0:${var.proxy_runtime_gid} /tls/tls.key",
            ])]

            secrets = [
              { name = "WIRE_TLS_CERT", valueFrom = "${aws_secretsmanager_secret.wire_tls.arn}:cert::" },
              { name = "WIRE_TLS_KEY", valueFrom = "${aws_secretsmanager_secret.wire_tls.arn}:key::" },
            ]

            mountPoints = [{ sourceVolume = "wire-tls", containerPath = "/tls", readOnly = false }]

            enable_cloudwatch_logging = true
          }

          proxy = {
            essential = true
            # Explicit drain budget: comfortably covers goproxy's 10s bounded drain before SIGKILL.
            stop_timeout = 30
            image        = var.images.proxy

            dependsOn   = [{ containerName = "tls-init", condition = "SUCCESS" }]
            mountPoints = [{ sourceVolume = "wire-tls", containerPath = "/tls", readOnly = true }]

            portMappings = [
              {
                name          = "wire"
                containerPort = ds.wire_port
                protocol      = "tcp"
              },
            ]

            environment = concat(
              [
                { name = "PM_ENGINE", value = ds.engine },
                { name = "PM_DATASOURCE_NAME", value = key },
                { name = "PM_PROXY_PORT", value = tostring(ds.wire_port) },
                # The address a client dials to reach this proxy, which the proxy cannot infer: its own
                # task IP is not reachable and changes on every deployment. Unset, the control plane has
                # no connect address for the datasource and pmon cannot broker it at all. The internal
                # NLB is that address — it has a listener per wire port and survives task replacement.
                { name = "PM_ADVERTISE_ADDR", value = "${module.internal_nlb.dns_name}:${ds.wire_port}" },
                { name = "PM_TLS_CERT", value = "/tls/tls.crt" },
                { name = "PM_TLS_KEY", value = "/tls/tls.key" },
                { name = "PM_CONTROL_PLANE_GRPC", value = "${module.internal_nlb.dns_name}:9090" },
                { name = "PM_MCP_RESOURCE", value = "https://${var.console_hostname}/mcp" },
              ],
              ds.engine == "athena" ? [
                { name = "AWS_REGION", value = local.aws_region },
                { name = "PM_TARGET_DB", value = ds.athena.database },
                { name = "PM_ATHENA_WORKGROUP", value = ds.athena.workgroup },
                { name = "PM_ATHENA_DEFAULT_CATALOG", value = ds.athena.catalog },
                ] : [
                { name = "PM_TARGET_HOST", value = ds.target.host },
                { name = "PM_TARGET_PORT", value = tostring(ds.target.port) },
                { name = "PM_TARGET_DB", value = ds.target.db },
              ],
              ds.engine == "athena" || try(ds.target.tls, "disable") == "disable" ? [] : [{ name = "PM_TARGET_TLS", value = ds.target.tls }],
              try(ds.target.ca, null) == null ? [] : [{ name = "PM_TARGET_CA", value = ds.target.ca }],
              ds.tags == "" ? [] : [{ name = "PM_DATASOURCE_TAGS", value = ds.tags }],
              ds.description == "" ? [] : [{ name = "PM_DATASOURCE_DESCRIPTION", value = ds.description }],
            )

            secrets = concat(
              [{ name = "PM_SECRET_TOKEN", valueFrom = aws_secretsmanager_secret.grpc_token.arn }],
              ds.engine == "athena" ? [] : [
                { name = "PM_TARGET_USER", valueFrom = "${aws_secretsmanager_secret.target_credentials[key].arn}:username::" },
                { name = "PM_TARGET_PASSWORD", valueFrom = "${aws_secretsmanager_secret.target_credentials[key].arn}:password::" },
              ],
            )

            enable_cloudwatch_logging = true
          }
        }

        subnet_ids = var.private_subnets

        task_exec_secret_arns = concat(
          [
            aws_secretsmanager_secret.grpc_token.arn,
            aws_secretsmanager_secret.wire_tls.arn,
          ],
          ds.engine == "athena" ? [] : [aws_secretsmanager_secret.target_credentials[key].arn],
        )

        # The Athena proxy is itself the Athena client: it queries as this task role, scoped to the
        # workgroup, the S3 prefixes, and this account's Glue catalog.
        tasks_iam_role_statements = ds.engine != "athena" ? null : concat([
          {
            actions = [
              "athena:GetWorkGroup",
              "athena:StartQueryExecution",
              "athena:GetQueryExecution",
              "athena:GetQueryResults",
              "athena:StopQueryExecution",
              "athena:GetPreparedStatement",
            ]
            resources = ["arn:aws:athena:${local.aws_region}:${local.aws_account_id}:workgroup/${ds.athena.workgroup}"]
          },
          {
            actions   = ["athena:GetDataCatalog", "athena:ListDatabases", "athena:GetDatabase", "athena:ListTableMetadata", "athena:GetTableMetadata"]
            resources = ["arn:aws:athena:${local.aws_region}:${local.aws_account_id}:datacatalog/${ds.athena.catalog}"]
          },
          {
            # Enumerations with no resource type: IAM accepts them only on "*".
            actions   = ["athena:ListDataCatalogs", "athena:ListWorkGroups"]
            resources = ["*"]
          },
          {
            actions = ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables", "glue:GetPartition", "glue:GetPartitions"]
            resources = [
              "arn:aws:glue:${local.aws_region}:${local.aws_account_id}:catalog",
              "arn:aws:glue:${local.aws_region}:${local.aws_account_id}:database/*",
              "arn:aws:glue:${local.aws_region}:${local.aws_account_id}:table/*/*",
            ]
          },
          {
            actions   = ["s3:GetBucketLocation"]
            resources = distinct([for prefix in concat([ds.athena.result_prefix], ds.athena.data_prefixes) : "arn:aws:s3:::${split("/", prefix)[0]}"])
          },
          ],
          # ListBucket is bucket-scoped, so the key prefixes are the condition; one statement per bucket
          # keeps one bucket's prefixes from applying to another.
          [for bucket in distinct([for prefix in concat([ds.athena.result_prefix], ds.athena.data_prefixes) : split("/", prefix)[0]]) : {
            actions   = ["s3:ListBucket"]
            resources = ["arn:aws:s3:::${bucket}"]
            condition = [{
              test     = "StringLike"
              variable = "s3:prefix"
              values = [
                for prefix in concat([ds.athena.result_prefix], ds.athena.data_prefixes) :
                "${join("/", slice(split("/", prefix), 1, length(split("/", prefix))))}*" if split("/", prefix)[0] == bucket
              ]
            }]
          }],
          [
            {
              actions   = ["s3:GetObject"]
              resources = [for prefix in ds.athena.data_prefixes : "arn:aws:s3:::${prefix}*"]
            },
            {
              actions   = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
              resources = ["arn:aws:s3:::${ds.athena.result_prefix}*"]
            },
        ])

        # Deterministic name so policies can carry it as a literal ARN; a reference would cycle.
        task_exec_iam_role_use_name_prefix = false
        task_exec_iam_role_name            = "proxy-${key}-task-exec"

        security_group_ids = ds.extra_security_group_ids

        security_group_ingress_rules = {
          nlb-wire = {
            from_port                    = ds.wire_port
            to_port                      = ds.wire_port
            ip_protocol                  = "tcp"
            referenced_security_group_id = module.internal_nlb.security_group_id
          }
        }
        security_group_egress_rules = {
          all = {
            ip_protocol = "-1"
            cidr_ipv4   = "0.0.0.0/0"
            description = "Backend DB, control-plane gRPC via NLB, ECR"
          }
        }

        desired_count      = 1
        enable_autoscaling = false

        requires_compatibilities = ["FARGATE"]
        launch_type              = "FARGATE"
        runtime_platform = {
          cpu_architecture        = "ARM64"
          operating_system_family = "LINUX"
        }

        load_balancer = {
          nlb-wire = {
            target_group_arn = module.internal_nlb.target_groups["wire/${key}"].arn
            container_name   = "proxy"
            container_port   = ds.wire_port
          }
        }
      }
    },
    {
      # The audit-trail monitor: it verifies the hash chain, signs anchors off-box into the
      # WORM bucket, and raises anomaly alerts. It serves no traffic, so it has no load
      # balancer, no ingress, and no port — a single task that polls the store on a timer.
      #
      # An audit trail that nothing verifies is a log. Deploying this is what makes the chain
      # tamper-EVIDENT rather than merely tamper-resistant: the signed anchors it writes are
      # the off-box witness a later re-anchor cannot forge, which is exactly why the bucket
      # is Object-Lock and the signing key is asymmetric and KMS-held.
      auditmon = {
        cpu    = var.auditmon_task_size.cpu
        memory = var.auditmon_task_size.memory

        volume = { auditmon-config = {} }

        container_definitions = {
          auditmon = {
            essential = true
            image     = var.images.auditmon

            environment = [
              { name = "AUDITMON_MONITOR_BUCKET", value = module.audit_bucket.s3_bucket_id },
              { name = "AUDITMON_MONITOR_KMS_KEY_ID", value = module.audit_signer_key.key_arn },
              { name = "AUDITMON_MONITOR_SIGNER_TYPE", value = "kms" },
              { name = "AUDITMON_MONITOR_SIGNER_KEY_ID", value = module.audit_signer_key.key_id },
              { name = "AUDITMON_CONFIG", value = local.auditmon_config_path },
              # The same store the control plane uses, passed as parts rather than a composed DSN, so
              # there is no second spelling of one credential to keep in step. Only the password is a
              # secret (below); the rest are ordinary configuration.
              { name = "AUDITMON_DB_HOST", value = module.aurora.cluster_endpoint },
              { name = "AUDITMON_DB_PORT", value = tostring(module.aurora.cluster_port) },
              { name = "AUDITMON_DB_NAME", value = "proxymonster" },
              { name = "AUDITMON_DB_USER", value = local.db_master_username },
            ]

            secrets = concat(
              [{ name = "AUDITMON_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.db_master.arn }],
              local.auditmon_slack_enabled ? [
                { name = "SLACK_WEBHOOK_URL", valueFrom = one(aws_secretsmanager_secret.alert_slack_webhook[*].arn) },
              ] : [],
            )

            # Read the config only after config-init has written it (it writes once and exits 0).
            dependsOn   = [{ containerName = "config-init", condition = "SUCCESS" }]
            mountPoints = [{ sourceVolume = "auditmon-config", containerPath = dirname(local.auditmon_config_path), readOnly = true }]

            enable_cloudwatch_logging = true
          }

          # No configmap on Fargate: like the wire proxy's tls-init, a throwaway container writes the
          # rendered config (always the rules; plus the Slack sink where enabled) to the shared volume.
          config-init = {
            essential  = false
            image      = "public.ecr.aws/docker/library/busybox:1.37"
            user       = "0"
            entrypoint = ["/bin/sh", "-c"]
            command = [join(" ", [
              "set -eu;",
              "printf %s \"$AUDITMON_CONFIG_YAML\" > ${local.auditmon_config_path}",
            ])]

            environment = [
              { name = "AUDITMON_CONFIG_YAML", value = local.auditmon_config_yaml },
            ]

            mountPoints = [{ sourceVolume = "auditmon-config", containerPath = dirname(local.auditmon_config_path), readOnly = false }]

            enable_cloudwatch_logging = true
          }
        }

        subnet_ids = var.private_subnets

        task_exec_secret_arns = concat(
          [aws_secretsmanager_secret.db_master.arn],
          local.auditmon_slack_enabled ? [one(aws_secretsmanager_secret.alert_slack_webhook[*].arn)] : [],
        )

        # Read the trail, write anchors, sign them, and verify them on read-back. Nothing here
        # can delete or overwrite an anchor: no DeleteObject, and the bucket's Object-Lock
        # retention would refuse it anyway.
        tasks_iam_role_statements = [
          {
            actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
            resources = [module.audit_bucket.s3_bucket_arn, "${module.audit_bucket.s3_bucket_arn}/*"]
          },
          {
            actions   = ["kms:Sign", "kms:Verify"]
            resources = [module.audit_signer_key.key_arn]
          },
        ]

        security_group_egress_rules = {
          all = {
            ip_protocol = "-1"
            cidr_ipv4   = "0.0.0.0/0"
            description = "Aurora, S3, KMS, Secrets Manager, CloudWatch Logs, ECR"
          }
        }

        desired_count      = 1
        enable_autoscaling = false

        requires_compatibilities = ["FARGATE"]
        launch_type              = "FARGATE"
        runtime_platform = {
          cpu_architecture        = "ARM64"
          operating_system_family = "LINUX"
        }
      }
    },
    var.tailscale == null ? {} : {
      (local.tailscale_service) = {
        cpu    = local.edge_enabled ? 512 : 256
        memory = local.edge_enabled ? 1024 : 512

        volume = merge({ tailscale-config = {} }, { for key, value in { edge-certs = {} } : key => value if local.edge_enabled })

        container_definitions = merge({
          tailscale = {
            essential = true
            image     = var.tailscale.image

            environment = [
              { name = "TS_HOSTNAME", value = local.tailscale_service },
              { name = "TS_USERSPACE", value = "true" },
              { name = "TS_CLIENT_ID", value = var.tailscale.client_id },
              { name = "TS_AUDIENCE", value = local.tailscale_audience },
              { name = "TS_EXTRA_ARGS", value = "--advertise-tags=${var.tailscale.tag}" },
              { name = "TS_ACCEPT_DNS", value = "false" },
              { name = "TS_TAILSCALED_EXTRA_ARGS", value = "--port=41641" },
              { name = "TS_ENABLE_HEALTH_CHECK", value = "true" },
              { name = "TS_LOCAL_ADDR_PORT", value = "0.0.0.0:8080" },
              { name = "TS_SERVE_CONFIG", value = local.tailscale_serve_config_path },
              { name = "AWS_REGION", value = local.aws_region },
            ]

            readonlyRootFilesystem = false

            dependsOn   = [{ containerName = "config-init", condition = "SUCCESS" }]
            mountPoints = [{ sourceVolume = "tailscale-config", containerPath = dirname(local.tailscale_serve_config_path), readOnly = true }]

            healthCheck = {
              command     = ["CMD-SHELL", "wget -q --spider http://127.0.0.1:8080/healthz || exit 1"]
              interval    = 30
              timeout     = 5
              retries     = 3
              startPeriod = 30
            }

            linuxParameters = {
              initProcessEnabled = true
            }

            enable_cloudwatch_logging = true
          }

          config-init = {
            essential  = false
            image      = "public.ecr.aws/docker/library/busybox:1.37"
            user       = "0"
            entrypoint = ["/bin/sh", "-c"]
            command = [join(" ", concat(
              [
                "set -eu;",
                "printf %s \"$TS_SERVE_CONFIG_JSON\" > ${local.tailscale_serve_config_path}",
              ],
              local.edge_enabled ? [
                "; printf %s \"$EDGE_CADDYFILE\" > ${local.edge_caddyfile_path}",
              ] : [],
            ))]

            environment = concat(
              [
                { name = "TS_SERVE_CONFIG_JSON", value = local.tailscale_serve_config },
              ],
              local.edge_enabled ? [
                { name = "EDGE_CADDYFILE", value = local.edge_caddyfile },
              ] : [],
            )

            mountPoints = [{ sourceVolume = "tailscale-config", containerPath = dirname(local.tailscale_serve_config_path), readOnly = false }]

            enable_cloudwatch_logging = true
          }
          }, { for key, value in {
            cert-init = {
              essential              = false
              image                  = try(local.tailscale_edge.cli_image, null)
              user                   = "0"
              entrypoint             = ["/bin/sh", "-c"]
              readonlyRootFilesystem = false
              command = [join(" ", [
                "set -eu; umask 077;",
                "EDGE_KEY_PASSPHRASE=$(python3 -c 'import secrets; print(secrets.token_hex(32))'); export EDGE_KEY_PASSPHRASE;",
                "printf %s \"$EDGE_KEY_PASSPHRASE\" > /tmp/passphrase;",
                "aws acm export-certificate --certificate-arn \"$EDGE_CERTIFICATE_ARN\" --passphrase fileb:///tmp/passphrase --output json > /tmp/export.json;",
                "jq -r '.Certificate, .CertificateChain' /tmp/export.json > ${local.edge_cert_dir}/cert.pem;",
                "jq -r '.PrivateKey' /tmp/export.json | python3 -c \"$EDGE_DECRYPT_KEY_PY\" > ${local.edge_cert_dir}/key.pem;",
                "rm -f /tmp/export.json /tmp/passphrase",
              ])]

              environment = [
                { name = "AWS_REGION", value = local.aws_region },
                { name = "EDGE_CERTIFICATE_ARN", value = try(local.tailscale_edge.certificate_arn, null) },
                { name = "EDGE_DECRYPT_KEY_PY", value = file("${path.module}/edge/decrypt_key.py") },
              ]

              mountPoints = [{ sourceVolume = "edge-certs", containerPath = local.edge_cert_dir, readOnly = false }]

              enable_cloudwatch_logging = true
            }

            caddy = {
              essential              = true
              image                  = try(local.tailscale_edge.caddy_image, null)
              command                = ["caddy", "run", "--config", local.edge_caddyfile_path, "--adapter", "caddyfile"]
              readonlyRootFilesystem = false

              dependsOn = [
                { containerName = "config-init", condition = "SUCCESS" },
                { containerName = "cert-init", condition = "SUCCESS" },
              ]
              mountPoints = [
                { sourceVolume = "tailscale-config", containerPath = dirname(local.tailscale_serve_config_path), readOnly = true },
                { sourceVolume = "edge-certs", containerPath = local.edge_cert_dir, readOnly = true },
              ]

              healthCheck = {
                command     = ["CMD-SHELL", "wget -q --spider http://127.0.0.1:${local.edge_health}/healthz || exit 1"]
                interval    = 30
                timeout     = 5
                retries     = 3
                startPeriod = 15
              }

              enable_cloudwatch_logging = true
            }
        } : key => value if local.edge_enabled })

        subnet_ids = var.private_subnets

        tasks_iam_role_name            = local.tailscale_tasks_role_name
        tasks_iam_role_use_name_prefix = false
        tasks_iam_role_statements = concat(
          [
            {
              actions   = ["sts:GetWebIdentityToken"]
              resources = ["*"]
              condition = [
                {
                  test     = "ForAllValues:StringEquals"
                  variable = "sts:IdentityTokenAudience"
                  values   = [local.tailscale_audience]
                },
                {
                  test     = "Null"
                  variable = "sts:IdentityTokenAudience"
                  values   = ["false"]
                },
                {
                  test     = "NumericLessThanEquals"
                  variable = "sts:DurationSeconds"
                  values   = ["300"]
                },
              ]
            },
          ],
          local.edge_enabled ? [
            {
              actions   = ["acm:ExportCertificate"]
              resources = [try(local.tailscale_edge.certificate_arn, null)]
            },
          ] : [],
        )

        security_group_ingress_rules = {
          wireguard = {
            from_port   = 41641
            to_port     = 41641
            ip_protocol = "udp"
            cidr_ipv4   = var.vpc_cidr
            description = "Tailscale WireGuard"
          }
        }
        security_group_egress_rules = {
          all = {
            ip_protocol = "-1"
            cidr_ipv4   = "0.0.0.0/0"
            description = "Tailscale control plane and DERP, console ALB, ECR, CloudWatch Logs"
          }
        }

        desired_count      = 1
        enable_autoscaling = false

        requires_compatibilities = ["FARGATE"]
        launch_type              = "FARGATE"
        runtime_platform = {
          cpu_architecture        = "ARM64"
          operating_system_family = "LINUX"
        }
      }
    },
  )
}
