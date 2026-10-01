locals {
  # Consume an existing wildcard cert instead of self-validating one here. Defaults to the
  # immediate-parent wildcard of the hostname; console_cert_domain overrides it when the
  # cert's primary domain is not that wildcard (e.g. the example.com cert covering *.example.com).
  console_cert_domain = coalesce(var.console_cert_domain, "*.${join(".", slice(split(".", var.console_hostname), 1, length(split(".", var.console_hostname))))}")

  # ELBv2 allows one subnet per AZ; a VPC may carry more than one,
  # so pick the largest block per AZ.
  lb_azs = sort(distinct([for s in data.aws_subnet.lb : s.availability_zone]))
  lb_subnets = [
    for az in local.lb_azs : sort([
      for s in data.aws_subnet.lb : s.id
      if s.availability_zone == az && tonumber(split("/", s.cidr_block)[1]) == min([
        for t in data.aws_subnet.lb : tonumber(split("/", t.cidr_block)[1])
        if t.availability_zone == az
      ]...)
    ])[0]
  ]
}

data "aws_subnet" "lb" {
  for_each = toset(var.private_subnets)
  id       = each.value
}

data "aws_acm_certificate" "console" {
  domain      = local.console_cert_domain
  statuses    = ["ISSUED"]
  most_recent = true
}

module "console_alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.0"

  name               = var.name
  load_balancer_type = "application"
  internal           = true
  vpc_id             = var.vpc_id
  subnets            = local.lb_subnets

  enable_deletion_protection = var.enable_lb_deletion_protection

  # The control-plane's /mcp gate compares the client-addressed host against PM_MCP_RESOURCE (a
  # DNS-rebinding defense the MCP spec calls for). An ALB otherwise replaces Host with its own
  # target authority and sends no X-Forwarded-Host, so every /mcp call would fail closed with
  # 403 mcp.invalid_host while /api and /auth keep working.
  preserve_host_header = true

  security_group_ingress_rules = merge(
    {
      http = {
        from_port   = 80
        to_port     = 80
        ip_protocol = "tcp"
        cidr_ipv4   = var.vpc_cidr
      }
      https = {
        from_port   = 443
        to_port     = 443
        ip_protocol = "tcp"
        cidr_ipv4   = var.vpc_cidr
      }
    },
    {
      for name, cidr in var.console_extra_ingress_cidrs : "http-${name}" => {
        from_port   = 80
        to_port     = 80
        ip_protocol = "tcp"
        cidr_ipv4   = cidr
      }
    },
    {
      for name, cidr in var.console_extra_ingress_cidrs : "https-${name}" => {
        from_port   = 443
        to_port     = 443
        ip_protocol = "tcp"
        cidr_ipv4   = cidr
      }
    },
  )

  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = var.vpc_cidr
    }
  }

  listeners = {
    http = {
      port     = 80
      protocol = "HTTP"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    https = {
      port            = 443
      protocol        = "HTTPS"
      certificate_arn = data.aws_acm_certificate.console.arn
      forward = {
        target_group_key = "web"
      }
      rules = {
        control-plane = {
          priority = 100
          conditions = [{
            path_pattern = {
              # The control-plane serves the RFC 8414/9728 discovery docs at the root
              # /.well-known/oauth-* (oauth-authorization-server, oauth-protected-resource
              # [/mcp]); route those to it too, else they fall through to the web default
              # and MCP auth discovery breaks.
              values = ["/api/*", "/auth/*", "/oauth/*", "/mcp*", "/.well-known/oauth-*"]
            }
          }]
          actions = [{
            forward = {
              target_group_key = "control-plane"
            }
          }]
        }
      }
    }
  }

  target_groups = {
    control-plane = {
      name              = "${var.name}-cp"
      protocol          = "HTTP"
      port              = 8080
      target_type       = "ip"
      create_attachment = false
      # ECS holds SIGTERM until the longest deregistration_delay across the task's groups; keep short (like the
      # NLB groups) so the control-plane's graceful drain fires promptly.
      deregistration_delay = 5
      health_check = {
        path                = "/health"
        interval            = 10
        healthy_threshold   = 2
        unhealthy_threshold = 2
      }
    }
    web = {
      name                 = "${var.name}-web"
      protocol             = "HTTP"
      port                 = 41300
      target_type          = "ip"
      create_attachment    = false
      deregistration_delay = 5
      health_check = {
        path                = "/"
        matcher             = "200-399"
        healthy_threshold   = 2
        unhealthy_threshold = 3
      }
    }
  }
}
