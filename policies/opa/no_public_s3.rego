package security

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────
# POLICY: No public S3 buckets
# Checks terraform plan JSON for public access violations
# ─────────────────────────────────────────────────────

deny[msg] if {
  # Find every S3 public access block resource in the plan
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"

  # Check if ANY of the 4 settings is false
  changes := resource.change.after

  not changes.block_public_acls == true

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' has block_public_acls=false. All 4 public access block settings must be true.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  changes := resource.change.after
  not changes.block_public_policy == true

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' has block_public_policy=false.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  changes := resource.change.after
  not changes.ignore_public_acls == true

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' has ignore_public_acls=false.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  changes := resource.change.after
  not changes.restrict_public_buckets == true

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' has restrict_public_buckets=false.",
    [resource.address]
  )
}
