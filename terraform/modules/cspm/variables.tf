variable "project_name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "kms_key_arn" {
  description = "KMS key for DynamoDB + Lambda encryption"
  type        = string
}

variable "logging_bucket_name" {
  description = "S3 bucket for Prowler reports"
  type        = string
}

variable "logging_bucket_arn" {
  description = "S3 bucket ARN for IAM policy scoping"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic for CSPM alerts (from CloudTrail module)"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
