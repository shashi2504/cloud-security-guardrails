output "s3_key_arn" {
  description = "KMS key ARN for S3 encryption"
  value       = aws_kms_key.s3.arn
}

output "s3_key_id" {
  description = "KMS key ID for S3 encryption"
  value       = aws_kms_key.s3.key_id
}

output "cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.arn
}

output "cloudtrail_key_id" {
  description = "KMS key ID for CloudTrail encryption"
  value       = aws_kms_key.cloudtrail.key_id
}

output "ebs_key_arn" {
  description = "KMS key ARN for EBS encryption"
  value       = aws_kms_key.ebs.arn
}

output "ebs_key_id" {
  description = "KMS key ID for EBS encryption"
  value       = aws_kms_key.ebs.key_id
}

output "rds_key_arn" {
  description = "KMS key ARN for RDS encryption"
  value       = aws_kms_key.rds.arn
}

output "rds_key_id" {
  description = "KMS key ID for RDS encryption"
  value       = aws_kms_key.rds.key_id
}

output "secrets_key_arn" {
  description = "KMS key ARN for Secrets Manager"
  value       = aws_kms_key.secrets.arn
}

output "secrets_key_id" {
  description = "KMS key ID for Secrets Manager"
  value       = aws_kms_key.secrets.key_id
}
