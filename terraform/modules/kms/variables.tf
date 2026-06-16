variable "project_name" {
  description = "Project name for resource naming and aliasing"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all KMS keys"
  type        = map(string)
  default     = {}
}
