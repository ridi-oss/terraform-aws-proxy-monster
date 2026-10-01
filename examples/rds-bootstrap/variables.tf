variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "private_subnets" {
  type = list(string)
}

variable "database_subnets" {
  type = list(string)
}

variable "data_account_id" {
  type = string
}

variable "apply_role_arn" {
  type        = string
  description = "The role that runs terraform apply in the proxy-monster account."
}

variable "orders_cluster_endpoint" {
  type = string
}

variable "orders_rds_arns" {
  type        = list(string)
  description = "The cluster ARN and its instance ARNs."
}

variable "image_tag" {
  type    = string
  default = "0.1.28"
}
