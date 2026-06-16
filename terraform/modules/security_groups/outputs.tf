output "alb_sg_id" {
  description = "ALB Security Group ID"
  value       = aws_security_group.alb.id
}

output "app_sg_id" {
  description = "Application Security Group ID"
  value       = aws_security_group.app.id
}

output "database_sg_id" {
  description = "Database Security Group ID"
  value       = aws_security_group.database.id
}

output "bastion_sg_id" {
  description = "Bastion Security Group ID"
  value       = aws_security_group.bastion.id
}

output "vpc_endpoints_sg_id" {
  description = "VPC Endpoints Security Group ID"
  value       = aws_security_group.vpc_endpoints.id
}
