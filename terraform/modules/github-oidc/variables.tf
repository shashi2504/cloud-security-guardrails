variable "github_org" {
  description = "GitHub organisation or username"
  type        = string
}

variable "github_repo" {
  description = "Repository name"
  type        = string
}

variable "name_prefix" {
  type    = string
  default = "csg-gha"
}

variable "state_bucket" {
  description = "Terraform state bucket the roles need access to"
  type        = string
}

variable "github_org_id" {
  description = "Numeric GitHub org/user ID, present in the OIDC subject claim"
  type        = string
}

variable "github_repo_id" {
  description = "Numeric GitHub repository ID, present in the OIDC subject claim"
  type        = string
}
