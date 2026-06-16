output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "scores_table_name" {
  value = aws_dynamodb_table.scores.name
}

output "scanner_lambda_arn" {
  value = aws_lambda_function.prowler_scanner.arn
}

output "scanner_lambda_name" {
  value = aws_lambda_function.prowler_scanner.function_name
}

output "dashboard_url" {
  value = "https://${local.region}.console.aws.amazon.com/cloudwatch/home#dashboards:name=${aws_cloudwatch_dashboard.cspm.dashboard_name}"
}
