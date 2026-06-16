# ═════════════════════════════════════════════════════
# STEP 1 — KMS FIRST
# All other modules need KMS key ARNs
# Nothing can be encrypted until keys exist
# ═════════════════════════════════════════════════════
module "kms" {
  source = "../../modules/kms"

  project_name = var.project_name

  tags = local.common_tags
}

# STEP 2 — VPC
# Network foundation — subnets, routing, flow logs
# Security Groups depend on VPC ID existing first
# ═════════════════════════════════════════════════════
module "vpc" {
  source = "../../modules/vpc"

  project_name           = var.project_name
  vpc_cidr               = var.vpc_cidr
  public_subnet_cidrs    = var.public_subnet_cidrs
  private_subnet_cidrs   = var.private_subnet_cidrs
  availability_zones     = var.availability_zones
  kms_cloudtrail_key_arn = module.kms.cloudtrail_key_arn
  tags                   = local.common_tags
}

# STEP 3 — SECURITY GROUPS
# Traffic rules — depends on VPC outputs
# ═════════════════════════════════════════════════════
module "security_groups" {
  source = "../../modules/security_groups"

  project_name         = var.project_name
  vpc_id               = module.vpc.vpc_id         # ← from VPC module
  vpc_cidr             = module.vpc.vpc_cidr_block # ← from VPC module
  private_subnet_cidrs = var.private_subnet_cidrs
  app_port             = var.app_port
  db_port              = var.db_port
  allowed_ssh_cidrs    = var.allowed_ssh_cidrs

  tags = local.common_tags
}

# ═════════════════════════════════════════════════════
# STEP 4 — S3
# Secure logging bucket — depends on KMS S3 key
# CloudTrail writes here in Step 6
# ═════════════════════════════════════════════════════
module "s3" {
  source = "../../modules/s3"

  project_name           = var.project_name
  kms_s3_key_arn         = module.kms.s3_key_arn # ← from KMS module
  kms_cloudtrail_key_arn = module.kms.cloudtrail_key_arn

  tags = local.common_tags
}

# ═════════════════════════════════════════════════════
# STEP 5 — IAM
# Roles for every service — depends on KMS key ARNs
# CloudTrail role ARN flows into CloudTrail module
# ═════════════════════════════════════════════════════
module "iam" {
  source = "../../modules/iam"

  project_name           = var.project_name
  kms_ebs_key_arn        = module.kms.ebs_key_arn        # ← from KMS module
  kms_secrets_key_arn    = module.kms.secrets_key_arn    # ← from KMS module
  kms_cloudtrail_key_arn = module.kms.cloudtrail_key_arn # ← from KMS module
  github_org             = var.github_org
  github_repo            = var.github_repo

  tags = local.common_tags
}

# ═════════════════════════════════════════════════════
# STEP 6 — CLOUDTRAIL
# Audit logging — depends on S3, KMS, IAM outputs
# Everything built above feeds into this final step
# ═════════════════════════════════════════════════════
module "cloudtrail" {
  source = "../../modules/cloudtrail"

  project_name           = var.project_name
  logging_bucket_name    = module.s3.logging_bucket_name  # ← from S3 module
  kms_cloudtrail_key_arn = module.kms.cloudtrail_key_arn  # ← from KMS module
  cloudtrail_role_arn    = module.iam.cloudtrail_role_arn # ← from IAM module
  alert_email            = var.alert_email

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────
# LOCAL VALUES
# Computed values used across all modules
# ─────────────────────────────────────────────────────
locals {
  common_tags = {
    CostCenter = var.cost_center
  }
}

# Add these two module blocks to environments/dev/main.tf

module "alerting" {
  source = "../../modules/alerting"

  project_name        = var.project_name
  environment         = var.environment
  sns_topic_arn       = module.cloudtrail.sns_topic_arn
  kms_key_arn         = module.kms.s3_key_arn
  kms_secrets_key_arn = module.kms.secrets_key_arn
  alert_email_from    = var.alert_email_from
  alert_email_domain  = var.alert_email_domain
  email_critical_to   = var.email_critical_to
  email_team_to       = var.email_team_to

  tags = local.common_tags
}

module "remediation" {
  source = "../../modules/remediation"

  project_name                = var.project_name
  environment                 = var.environment
  kms_key_arn                 = module.kms.s3_key_arn
  sns_topic_arn               = module.cloudtrail.sns_topic_arn
  lambda_remediation_role_arn = module.iam.lambda_remediation_role_arn
  dry_run                     = true    # Flip to false when ready for live

  tags = local.common_tags
}
