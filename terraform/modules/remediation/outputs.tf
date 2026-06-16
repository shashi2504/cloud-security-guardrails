output "remediation_engine_arn" {
  value = aws_lambda_function.remediation_engine.arn
}

output "audit_table_name" {
  value = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  value = aws_dynamodb_table.audit.arn
}
