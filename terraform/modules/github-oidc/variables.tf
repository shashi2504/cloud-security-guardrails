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
