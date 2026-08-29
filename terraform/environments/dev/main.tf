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

module "remediation" {
  source = "../../modules/remediation"

  source_dir  = "${path.root}/../../../remediation/lambda"
  kms_key_arn = module.kms.key_arn

  # Dry-run. Flipped to true only for the enforcement demo, then back.
  enforce = false
}

module "github_oidc" {
  source = "../../modules/github-oidc"

  github_org     = "shashi2504"
  github_org_id  = "95679221"
  github_repo    = "cloud-security-guardrails"
  github_repo_id = "1349996686"
  state_bucket   = "csg-tfstate-880636108185"
}
