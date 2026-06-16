# ─────────────────────────────────────────────────────
# TERRAFORM SETTINGS
# ─────────────────────────────────────────────────────
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # ── Remote State Backend ───────────────────────────
  # SECURITY: State stored encrypted in S3
  # State lock via DynamoDB prevents concurrent applies
  # Never use local state for team/production work
  backend "s3" {
    bucket         = "cloud-security-guardrail-terraform-state" # Replace before apply
    key            = "environments/dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true                                       # SSE-S3 encryption
    dynamodb_table = "cloud-security-guardrail-terraform-locks" # Replace before apply
  }
}

# ─────────────────────────────────────────────────────
# AWS PROVIDER
# ─────────────────────────────────────────────────────
provider "aws" {
  region = var.aws_region

  # SECURITY: Tag every resource automatically
  # Untagged resources = unknown ownership = security risk
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
    }
  }
}
# managed by terraform
# managed by terraform
