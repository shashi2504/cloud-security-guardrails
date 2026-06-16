# ─────────────────────────────────────────────────────
# NETWORKING OUTPUTS
# ─────────────────────────────────────────────────────
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs - use for EC2, RDS"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs - use for ALB"
  value       = module.vpc.public_subnet_ids
}

# ─────────────────────────────────────────────────────
# SECURITY GROUP OUTPUTS
# ─────────────────────────────────────────────────────
output "alb_sg_id" {
  description = "ALB security group ID"
  value       = module.security_groups.alb_sg_id
}

output "app_sg_id" {
  description = "App tier security group ID"
  value       = module.security_groups.app_sg_id
}

output "database_sg_id" {
  description = "Database security group ID"
  value       = module.security_groups.database_sg_id
}

# ─────────────────────────────────────────────────────
# KMS OUTPUTS
# ─────────────────────────────────────────────────────
output "kms_s3_key_arn" {
  description = "KMS key ARN for S3"
  value       = module.kms.s3_key_arn
}

output "kms_ebs_key_arn" {
  description = "KMS key ARN for EBS"
  value       = module.kms.ebs_key_arn
}

output "kms_rds_key_arn" {
  description = "KMS key ARN for RDS"
  value       = module.kms.rds_key_arn
}

# ─────────────────────────────────────────────────────
# IAM OUTPUTS
# ─────────────────────────────────────────────────────
output "ec2_instance_profile_name" {
  description = "EC2 instance profile - attach to all EC2 instances"
  value       = module.iam.ec2_instance_profile_name
}

output "cicd_deployment_role_arn" {
  description = "CI/CD role ARN - paste into GitHub Actions workflow"
  value       = module.iam.cicd_deployment_role_arn
}

output "security_audit_role_arn" {
  description = "Prowler audit role ARN - used in Phase 3"
  value       = module.iam.security_audit_role_arn
}

output "lambda_remediation_role_arn" {
  description = "Lambda remediation role ARN - used in Phase 6"
  value       = module.iam.lambda_remediation_role_arn
}

# ─────────────────────────────────────────────────────
# LOGGING OUTPUTS
# ─────────────────────────────────────────────────────
output "logging_bucket_name" {
  description = "Central logging bucket name"
  value       = module.s3.logging_bucket_name
}

output "cloudtrail_log_group" {
  description = "CloudWatch log group for CloudTrail"
  value       = module.cloudtrail.cloudwatch_log_group_name
}

output "security_alerts_sns_arn" {
  description = "SNS topic ARN for security alerts"
  value       = module.cloudtrail.sns_topic_arn
}
