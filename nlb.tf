# Internal NLB carrying every non-console path: control-plane HTTP (web rewrites +
# pmon-independent API), control-plane gRPC (proxy registration/decisions), and one
# SQL-wire listener per datasource. The gRPC and wire ports are never public.
module "internal_nlb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 10.0"

  name               = "${var.name}-internal"
  load_balancer_type = "network"
  internal           = true
  vpc_id             = var.vpc_id
  subnets            = local.lb_subnets

  enable_deletion_protection       = var.enable_lb_deletion_protection
  enable_cross_zone_load_balancing = true

  security_group_ingress_rules = merge(
    {
      cp-http = {
        from_port   = 8080
        to_port     = 8080
        ip_protocol = "tcp"
        cidr_ipv4   = var.vpc_cidr
      }
      cp-grpc = {
        from_port   = 9090
        to_port     = 9090
        ip_protocol = "tcp"
        cidr_ipv4   = var.vpc_cidr
      }
    },
    {
      for key, ds in var.datasources : "wire/${key}" => {
        from_port   = ds.wire_port
        to_port     = ds.wire_port
        ip_protocol = "tcp"
        cidr_ipv4   = var.vpc_cidr
      }
    },
  )

  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = var.vpc_cidr
    }
  }

  listeners = merge(
    {
      cp-http = {
        port     = 8080
        protocol = "TCP"
        forward = {
          target_group_key = "cp-http"
        }
      }
      cp-grpc = {
        port     = 9090
        protocol = "TCP"
        forward = {
          target_group_key = "cp-grpc"
        }
      }
    },
    {
      for key, ds in var.datasources : "wire/${key}" => {
        port     = ds.wire_port
        protocol = "TCP"
        forward = {
          target_group_key = "wire/${key}"
        }
      }
    },
  )

  target_groups = merge(
    {
      # cp-grpc carries the proxy's Events stream, cp-http the internal HTTP. Short delay so ECS SIGTERMs
      # promptly and the control-plane's GOAWAY drain fires; no connection_termination so GOAWAY rides the
      # open socket rather than the LB resetting it first. Fast health check for a quick first check.
      cp-http = {
        name                 = "${var.name}-cp-http"
        protocol             = "TCP"
        port                 = 8080
        target_type          = "ip"
        create_attachment    = false
        deregistration_delay = 5
        health_check = {
          # protocol is already TCP by default, but a health_check block without an explicit protocol makes
          # the aws provider send an empty healthCheckPath, which the API rejects for a TCP group
          # (hashicorp/terraform-provider-aws#25338). Naming TCP here keeps the path out of the request.
          protocol            = "TCP"
          interval            = 10
          healthy_threshold   = 2
          unhealthy_threshold = 2
        }
      }
      cp-grpc = {
        name                 = "${var.name}-cp-grpc"
        protocol             = "TCP"
        port                 = 9090
        target_type          = "ip"
        create_attachment    = false
        deregistration_delay = 5
        health_check = {
          # protocol is already TCP by default, but a health_check block without an explicit protocol makes
          # the aws provider send an empty healthCheckPath, which the API rejects for a TCP group
          # (hashicorp/terraform-provider-aws#25338). Naming TCP here keeps the path out of the request.
          protocol            = "TCP"
          interval            = 10
          healthy_threshold   = 2
          unhealthy_threshold = 2
        }
      }
    },
    {
      # A target-group name is capped at 32 characters by the API, which leaves little room once the
      # module prefix and "-wire-" are spent: a key like dev-as-prod-mysql overruns it. The wire port is
      # unique per datasource and already the thing this group routes, so it names the group — a
      # datasource key can then be as descriptive as it needs without a rename becoming a plan failure.
      for key, ds in var.datasources : "wire/${key}" => {
        name              = "${var.name}-wire-${ds.wire_port}"
        protocol          = "TCP"
        port              = ds.wire_port
        target_type       = "ip"
        create_attachment = false
        # Short so the proxy's graceful drain fires promptly; no connection_termination so the drain — not the
        # LB — closes in-flight client sessions. Health check like cp-* (protocol named to dodge aws#25338) so a
        # replacement is healthy in ~20s, not the ~150s TCP default, before the old task starts draining.
        deregistration_delay = 5
        health_check = {
          protocol            = "TCP"
          interval            = 10
          healthy_threshold   = 2
          unhealthy_threshold = 2
        }
      }
    },
  )
}
