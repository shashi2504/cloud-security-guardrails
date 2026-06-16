variable "project_name" { 
  type = string 
}

variable "environment" { 
  type = string
  default = "dev" 
}

variable "sns_topic_arn" {
  type = string 
}

variable "kms_key_arn" { 
  type = string 
}

variable "kms_secrets_key_arn" { 
  type = string 
}

variable "alert_email_from" { 
  type = string 
}

variable "alert_email_domain" { 
  type = string 
}

variable "email_critical_to" { 
  type = string 
}

variable "email_team_to" {
  type = string 
}

variable "tags" { 
  type = map(string)
  default = {} 
}
