variable "name" {
  description = "Name for the function and its role"
  type        = string
  default     = "csg-auto-remediation"
}

variable "source_dir" {
  description = "Directory containing handler.py"
  type        = string
}

variable "enforce" {
  description = "When false the function logs the API call it would make and returns without acting. Default false — enforcement is opt-in."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "CMK for the function's log group"
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 7
}
