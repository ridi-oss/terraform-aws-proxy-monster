locals {
  tailscale_edge  = try(var.tailscale.edge, null)
  edge_enabled    = local.tailscale_edge != null
  edge_cert_dir   = "/certs"
  edge_https_port = 8443
  edge_http_port  = 8880
  edge_health     = 8881

  edge_upstream_ports = {
    cp-http = 8080
    web     = 41300
  }

  edge_target_group_arns_after_listeners = {
    for key in keys(local.edge_upstream_ports) : key => (
      module.edge_nlb[0].listeners[key].arn == null ? null : module.edge_nlb[0].target_groups[key].arn
    ) if local.edge_enabled
  }

  edge_caddyfile_path = "${dirname(local.tailscale_serve_config_path)}/Caddyfile"
  edge_caddyfile = !local.edge_enabled ? "" : templatefile("${path.module}/edge/Caddyfile.tftpl", {
    https_port             = local.edge_https_port
    http_port              = local.edge_http_port
    health_port            = local.edge_health
    cert_dir               = local.edge_cert_dir
    control_plane_paths    = "/api/* /auth/* /oauth/* /mcp* /.well-known/oauth-*"
    control_plane_upstream = "${module.edge_nlb[0].dns_name}:${local.edge_upstream_ports.cp-http}"
    web_upstream           = "${module.edge_nlb[0].dns_name}:${local.edge_upstream_ports.web}"
  })
}

module "edge_nlb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.0"

  count = local.edge_enabled ? 1 : 0

  name               = "${var.name}-tailscale"
  load_balancer_type = "network"
  internal           = true
  vpc_id             = var.vpc_id
  subnets            = local.lb_subnets

  enable_deletion_protection       = var.enable_lb_deletion_protection
  enable_cross_zone_load_balancing = true

  security_group_ingress_rules = {}
  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = var.vpc_cidr
    }
  }

  listeners = {
    for key, port in local.edge_upstream_ports : key => {
      port     = port
      protocol = "TCP"
      forward = {
        target_group_key = key
      }
    }
  }

  target_groups = {
    for key, port in local.edge_upstream_ports : key => {
      name                 = "${var.name}-ts-${key}"
      protocol             = "TCP"
      port                 = port
      target_type          = "ip"
      create_attachment    = false
      deregistration_delay = 5
      health_check = {
        protocol            = "TCP"
        interval            = 10
        healthy_threshold   = 2
        unhealthy_threshold = 2
      }
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "edge_nlb_from_tailscale" {
  for_each = local.edge_enabled ? local.edge_upstream_ports : {}

  security_group_id            = module.edge_nlb[0].security_group_id
  referenced_security_group_id = module.ecs.services[local.tailscale_service].security_group_id
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
  description                  = "Caddy on the tailscale host"
}

module "edge_redeploy" {
  source  = "terraform-aws-modules/eventbridge/aws"
  version = "~> 3.13"

  count = local.edge_enabled ? 1 : 0

  create_bus       = false
  create_schedules = true

  role_name                = "${var.name}-tailscale-redeploy"
  attach_policy_statements = true
  policy_statements = {
    update_service = {
      actions   = ["ecs:UpdateService"]
      resources = ["arn:aws:ecs:${local.aws_region}:${local.aws_account_id}:service/${var.name}/${local.tailscale_service}"]
    }
  }

  schedules = {
    "${var.name}-tailscale-redeploy" = {
      description         = "Restart the tailscale host so it exports the renewed console certificate"
      schedule_expression = try(local.tailscale_edge.redeploy_schedule, null)
      arn                 = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
      input = jsonencode({
        Cluster            = var.name
        Service            = local.tailscale_service
        ForceNewDeployment = true
      })
    }
  }
}
