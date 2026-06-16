variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "logging_bucket_name" {
  description = "S3 logging bucket name (from S3 module)"
  type        = string
}

variable "kms_cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail encryption (from KMS module)"
  type        = string
}

variable "cloudtrail_role_arn" {
  description = "IAM role ARN for CloudTrail → CloudWatch (from IAM module)"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts (leave empty to skip)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
