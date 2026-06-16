output "trail_arn" {
  description = "CloudTrail trail ARN"
  value       = aws_cloudtrail.main.arn
}

output "trail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.main.name
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}
