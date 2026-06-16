# ─────────────────────────────────────────────────────
# PROJECT
# ─────────────────────────────────────────────────────
variable "project_name" {
  description = "Project name — used in all resource names"
  type        = string
  default     = "cloud-sec-guardrails"

  validation {
    condition     = length(var.project_name) <= 40
    error_message = "Project name must be 20 chars or less — used in S3 bucket names."
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "owner" {
  description = "Team or person responsible for this environment"
  type        = string
}

variable "cost_center" {
  description = "Cost center for billing allocation"
  type        = string
}

# ─────────────────────────────────────────────────────
# AWS
# ─────────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

# ─────────────────────────────────────────────────────
# NETWORKING
# ─────────────────────────────────────────────────────
variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "availability_zones" {
  description = "AZs to deploy into — must match subnet count"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones required for HA."
  }
}

# ─────────────────────────────────────────────────────
# SECURITY GROUPS
# ─────────────────────────────────────────────────────
variable "app_port" {
  description = "Application port"
  type        = number
  default     = 8080
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 5432
}

variable "allowed_ssh_cidrs" {
  description = "IPs allowed to SSH to bastion — NEVER 0.0.0.0/0"
  type        = list(string)

  validation {
    condition     = !contains(var.allowed_ssh_cidrs, "0.0.0.0/0")
    error_message = "SECURITY: SSH must never be open to 0.0.0.0/0."
  }
}

# ─────────────────────────────────────────────────────
# CI/CD
# ─────────────────────────────────────────────────────
variable "github_org" {
  description = "GitHub org for OIDC trust policy"
  type        = string
}

variable "github_repo" {
  description = "GitHub repo for OIDC trust policy"
  type        = string
}

# ─────────────────────────────────────────────────────
# ALERTING
# ─────────────────────────────────────────────────────
variable "alert_email" {
  description = "Email for security alerts — leave empty to skip"
  type        = string
  default     = ""
}

variable "alert_email_from" {
  description = "Verified SES sender address for security alert emails"
  type        = string
}

variable "alert_email_domain" {
  description = "Domain to verify in SES for sending alert emails"
  type        = string
}

variable "email_critical_to" {
  description = "Email address that receives CRITICAL severity alerts"
  type        = string
}

variable "email_team_to" {
  description = "Email address that receives HIGH/team-wide alerts"
  type        = string
}
