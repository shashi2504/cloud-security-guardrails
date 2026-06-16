output "alert_router_lambda_arn" {
  value = aws_lambda_function.alert_router.arn
}

output "alert_dedup_table_name" {
  value = aws_dynamodb_table.alert_dedup.name
}

output "slack_secret_arn" {
  value = aws_secretsmanager_secret.slack_webhook.arn
}

output "ses_domain_verification_token" {
  description = "Add this as a TXT record in your DNS to verify SES domain"
  value       = aws_ses_domain_identity.alerts.verification_token
}
