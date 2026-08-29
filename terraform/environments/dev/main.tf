data "aws_availability_zones" "available" {
  state = "available"
}

module "kms" {
  source = "../../modules/kms"

  name        = "csg-dev"
  description = "CMK for cloud-security-guardrails dev landing zone"
}

module "vpc" {
  source = "../../modules/vpc"

  name               = "csg-dev"
  cidr_block         = "10.0.0.0/16"
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
  kms_key_arn        = module.kms.key_arn
}

module "logging" {
  source = "../../modules/logging"

  name        = "csg-dev"
  trail_name  = "csg-dev-trail"
  kms_key_arn = module.kms.key_arn
}
