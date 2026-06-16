variable "project_name" {
  description = "Project name for bucket naming"
  type        = string
}

variable "kms_s3_key_arn" {
  description = "KMS key ARN for S3 encryption (from KMS module)"
  type        = string
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

variable "kms_cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail (from KMS module)"
  type        = string
}
