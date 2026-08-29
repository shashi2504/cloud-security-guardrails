variable "name" {
  description = "Name prefix / alias suffix for the key"
  type        = string
}

variable "description" {
  description = "Key description"
  type        = string
  default     = "Customer-managed key for cloud-security-guardrails"
}

variable "deletion_window_days" {
  description = "Waiting period before key deletion completes"
  type        = number
  default     = 7
}
