variable "project_name" {
  type = string 
}

variable "vpc_id" { 
  type = string 
}

variable "private_subnet_ids" { 
  type = list(string) 
}

variable "alb_sg_id" { 
  type = string 
}

variable "kms_key_arn" {
  type = string 
}

variable "logging_bucket_name" { 
  type = string 
}

variable "findings_table_name" {
  type = string 
}

variable "findings_table_arn" { 
  type = string 
}

variable "scores_table_name" { 
  type = string 
}

variable "scores_table_arn" { 
  type = string 
}

variable "sns_topic_arn" { 
  type = string 
}

variable "acm_certificate_arn" { 
  type = string 
}

variable "grafana_domain" { 
  type = string 
}

variable "grafana_admin_secret_arn" { 
  type = string 
}
variable "tags" { 
  type = map(string)
  default = {} 
}
