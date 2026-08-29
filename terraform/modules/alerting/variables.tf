variable "name" {
  description = "Name for the topic"
  type        = string
  default     = "csg-security-alerts"
}

variable "kms_key_arn" {
  description = "CMK for topic encryption"
  type        = string
}

variable "email_endpoint" {
  description = "Email address to subscribe. Requires manual confirmation via the link AWS sends."
  type        = string
}
