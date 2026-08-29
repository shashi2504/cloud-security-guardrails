output "plan_role_arn" {
  value = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  value = aws_iam_role.apply.arn
}

output "provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}

output "prowler_role_arn" {
  value = aws_iam_role.prowler.arn
}
