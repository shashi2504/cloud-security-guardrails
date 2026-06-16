package security

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────
# POLICY: Logging must be enabled everywhere
# CloudTrail, VPC Flow Logs, S3 access logs all required
# ─────────────────────────────────────────────────────

# CloudTrail must be enabled
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"

  not resource.change.after.enable_logging == true

  msg := sprintf(
    "POLICY VIOLATION: CloudTrail '%s' has enable_logging=false. Audit logging must always be active.",
    [resource.address]
  )
}

# CloudTrail must be multi-region
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"

  not resource.change.after.is_multi_region_trail == true

  msg := sprintf(
    "POLICY VIOLATION: CloudTrail '%s' must be multi-region. Single-region trails create blind spots.",
    [resource.address]
  )
}

# CloudTrail must have log file validation
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"

  not resource.change.after.enable_log_file_validation == true

  msg := sprintf(
    "POLICY VIOLATION: CloudTrail '%s' must have log file validation enabled.",
    [resource.address]
  )
}

# S3 buckets must have access logging configured
deny[msg] if {
  # Find all S3 buckets in plan
  bucket := input.resource_changes[_]
  bucket.type == "aws_s3_bucket"

  bucket_name := bucket.change.after.bucket

  # Check if there's a corresponding logging resource
  logging_resources := [r |
    r := input.resource_changes[_]
    r.type == "aws_s3_bucket_logging"
  ]

  # If no logging resource references this bucket — violation
  count([r | r := logging_resources[_]; r.change.after.bucket == bucket_name]) == 0

  # Exclude the access-logs bucket itself (avoids circular logging)
  not contains(bucket_name, "access-logs")

  msg := sprintf(
    "POLICY VIOLATION: S3 bucket '%s' has no access logging configured.",
    [bucket.address]
  )
}

# VPC must have flow logs enabled
deny[msg] if {
  vpc := input.resource_changes[_]
  vpc.type == "aws_vpc"

  vpc_id := vpc.change.after_unknown.id

  flow_logs := [r |
    r := input.resource_changes[_]
    r.type == "aws_flow_log"
  ]

  count(flow_logs) == 0

  msg := sprintf(
    "POLICY VIOLATION: VPC '%s' has no flow logs configured. Network traffic must be logged.",
    [vpc.address]
  )
}
