output "role_arn" {
  description = "ARN of the delegated read-only role."
  value       = module.role.arn
}

output "role_name" {
  description = "Name of the delegated read-only role."
  value       = module.role.name
}
