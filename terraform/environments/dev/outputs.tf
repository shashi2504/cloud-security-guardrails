output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnet_ids" {
  value = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  value = module.vpc.public_subnet_ids
}

output "kms_key_arn" {
  value = module.kms.key_arn
}

output "cloudtrail_bucket" {
  value = module.logging.bucket_name
}

output "cloudtrail_arn" {
  value = module.logging.trail_arn
}

output "gha_plan_role_arn" {
  value = module.github_oidc.plan_role_arn
}

output "gha_apply_role_arn" {
  value = module.github_oidc.apply_role_arn
}

output "alert_topic_arn" {
  value = module.alerting.topic_arn
}

output "gha_prowler_role_arn" {
  value = module.github_oidc.prowler_role_arn
}
