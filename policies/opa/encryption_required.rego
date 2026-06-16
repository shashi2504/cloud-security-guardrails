package security

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────
# POLICY: KMS encryption mandatory on all storage
# S3, EBS, RDS must use KMS — not AWS managed keys
# ─────────────────────────────────────────────────────

# S3 must use KMS encryption (not AES256)
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"

  rule := resource.change.after.rule[_]
  defaults := rule.apply_server_side_encryption_by_default[_]

  defaults.sse_algorithm != "aws:kms"

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' must use aws:kms encryption, not '%s'.",
    [resource.address, defaults.sse_algorithm]
  )
}

# S3 KMS key must be explicitly set (no AWS managed fallback)
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"

  rule := resource.change.after.rule[_]
  defaults := rule.apply_server_side_encryption_by_default[_]

  defaults.sse_algorithm == "aws:kms"

  # kms_master_key_id must be set and non-empty
  not defaults.kms_master_key_id

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' uses aws:kms but no KMS key specified. Must use project KMS key.",
    [resource.address]
  )
}

# KMS keys must have rotation enabled
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_kms_key"

  not resource.change.after.enable_key_rotation == true

  msg := sprintf(
    "POLICY VIOLATION: KMS key '%s' must have enable_key_rotation=true.",
    [resource.address]
  )
}

# KMS deletion window must be >= 7 days
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_kms_key"

  resource.change.after.deletion_window_in_days < 7

  msg := sprintf(
    "POLICY VIOLATION: KMS key '%s' deletion_window_in_days=%d is below minimum of 7.",
    [resource.address, resource.change.after.deletion_window_in_days]
  )
}
