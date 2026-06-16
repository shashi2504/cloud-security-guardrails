variable "project_name" { 
  type = string 
}

variable "environment" { 
  type = string
  default = "dev" 
}

variable "kms_key_arn" { 
  type = string 
}

variable "sns_topic_arn" { 
  type = string 
}

variable "lambda_remediation_role_arn" { 
  type = string 
}

variable "dry_run" {
  type        = bool
  default     = true    # SAFE DEFAULT — always start in dry run
  description = "Dry run mode — log actions without applying. Set false for live remediation."
}

variable "tags" { 
  type = map(string)
  default = {} 
}
