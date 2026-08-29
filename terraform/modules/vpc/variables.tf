variable "name" {
  description = "Name prefix for all resources in this module"
  type        = string
}

variable "cidr_block" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs to spread subnets across"
  type        = list(string)
}

variable "flow_log_retention_days" {
  description = "CloudWatch retention for VPC flow logs. Kept short to control cost."
  type        = number
  default     = 1
}

variable "kms_key_arn" {
  description = "CMK for encrypting flow logs"
  type        = string
}
