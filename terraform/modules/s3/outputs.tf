output "logging_bucket_id" {
  description = "Main logging bucket ID"
  value       = aws_s3_bucket.logging.id
}

output "logging_bucket_arn" {
  description = "Main logging bucket ARN"
  value       = aws_s3_bucket.logging.arn
}

output "logging_bucket_name" {
  description = "Main logging bucket name"
  value       = aws_s3_bucket.logging.bucket
}

output "access_logs_bucket_id" {
  description = "Access logs bucket ID"
  value       = aws_s3_bucket.access_logs.id
}

output "access_logs_bucket_arn" {
  description = "Access logs bucket ARN"
  value       = aws_s3_bucket.access_logs.arn
}
