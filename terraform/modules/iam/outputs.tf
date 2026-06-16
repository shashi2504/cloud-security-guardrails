output "ec2_instance_profile_name" {
  description = "EC2 instance profile name"
  value       = aws_iam_instance_profile.ec2.name
}

output "ec2_instance_role_arn" {
  description = "EC2 instance role ARN"
  value       = aws_iam_role.ec2_instance.arn
}

output "cloudtrail_role_arn" {
  description = "CloudTrail IAM role ARN"
  value       = aws_iam_role.cloudtrail.arn
}

output "lambda_remediation_role_arn" {
  description = "Lambda remediation role ARN"
  value       = aws_iam_role.lambda_remediation.arn
}

output "security_audit_role_arn" {
  description = "Security audit role ARN (for Prowler)"
  value       = aws_iam_role.security_audit.arn
}

output "cicd_deployment_role_arn" {
  description = "CI/CD deployment role ARN (for GitHub Actions)"
  value       = aws_iam_role.cicd_deployment.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC provider ARN"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}
