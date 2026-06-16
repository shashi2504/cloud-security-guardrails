output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_id" {
  description = "NAT Gateway ID"
  value       = aws_nat_gateway.main.id
}

output "vpc_cidr_block" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "vpc_flow_log_group_name" {
  description = "VPC flow log CloudWatch log group name"
  value       = aws_cloudwatch_log_group.vpc_flow_log.name
}
