variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "kms_ebs_key_arn" {
  description = "KMS key ARN for EBS (from KMS module)"
  type        = string
}

variable "kms_secrets_key_arn" {
  description = "KMS key ARN for Secrets Manager (from KMS module)"
  type        = string
}

variable "kms_cloudtrail_key_arn" {
  description = "KMS key ARN for CloudTrail (from KMS module)"
  type        = string
}

variable "github_org" {
  description = "GitHub organization name for OIDC trust"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name for OIDC trust"
  type        = string
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
