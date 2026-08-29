variable "name" {
  description = "Name prefix for logging resources"
  type        = string
}

variable "kms_key_arn" {
  description = "CMK used to encrypt log objects"
  type        = string
}

variable "trail_name" {
  description = "Name of the CloudTrail that will write to this bucket"
  type        = string
}

variable "log_retention_days" {
  description = "Days before log objects expire. Short by default to control cost."
  type        = number
  default     = 30
}
