variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID to attach security groups to"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (used for bastion egress)"
  type        = list(string)
}

variable "app_port" {
  description = "Port the application runs on"
  type        = number
  default     = 8080
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 5432 # PostgreSQL default
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to SSH into bastion — NEVER use 0.0.0.0/0"
  type        = list(string)

  validation {
    condition     = !contains(var.allowed_ssh_cidrs, "0.0.0.0/0")
    error_message = "SECURITY VIOLATION: SSH must not be open to 0.0.0.0/0"
  }
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
