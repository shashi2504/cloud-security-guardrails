# ─────────────────────────────────────────────────────
# DATA SOURCES
# ─────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ─────────────────────────────────────────────────────
# CLOUDWATCH LOG GROUP
# CloudTrail streams here for real-time monitoring
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "aws-cloudtrail-logs-${var.project_name}"
  retention_in_days = 90 # 90 days hot storage, rest in S3 Glacier

  # SECURITY: Encrypt CloudWatch logs with KMS
  kms_key_id = var.kms_cloudtrail_key_arn

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cloudtrail-logs"
    Purpose = "AuditLogging"
  })
}

# ─────────────────────────────────────────────────────
# CLOUDTRAIL — MAIN TRAIL
# Multi-region, all events, encrypted, validated
# ─────────────────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name = "${var.project_name}-main-trail"

  # NOTE: logging_bucket_name must be passed from S3 module output
  # to ensure bucket policy exists before trail creation
  # Do NOT hardcode this value

  s3_bucket_name = var.logging_bucket_name
  s3_key_prefix  = "cloudtrail"

  # SECURITY: Encrypt all log files with KMS
  kms_key_id = var.kms_cloudtrail_key_arn

  # SECURITY: Catch activity in every region
  # Single-region trails miss attacks in other regions
  is_multi_region_trail = true

  # SECURITY: Global services (IAM, STS, Route53) logged
  include_global_service_events = true

  # SECURITY: Detect log file tampering
  # SHA-256 hash chain — any modification is detectable
  enable_log_file_validation = true

  # Enabled from day 1
  enable_logging = true

  # Stream to CloudWatch for real-time alerting
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = var.cloudtrail_role_arn

  # ── Management Events ──────────────────────────────
  # Captures: CreateUser, DeleteBucket, ModifySecurityGroup
  # i.e. ALL control plane operations
  event_selector {
    read_write_type           = "All" # Both reads and writes
    include_management_events = true

    # ── S3 Data Events ────────────────────────────────
    # Captures: GetObject, PutObject, DeleteObject
    # Critical for detecting data exfiltration
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"] # ALL S3 buckets
    }

    # ── Lambda Data Events ────────────────────────────
    # Captures every Lambda invocation
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"] # ALL Lambda functions
    }
  }

  # ── Insight Events ─────────────────────────────────
  # SECURITY: Detects unusual API call volumes
  # Catches credential stuffing, automated attacks
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-main-trail"
    Purpose = "AuditLogging"
  })

  depends_on = [aws_cloudwatch_log_group.cloudtrail]
}

# ═════════════════════════════════════════════════════
# CLOUDWATCH METRIC FILTERS + ALARMS
# Real-time detection of critical security events
# Each filter → metric → alarm → SNS notification
# ═════════════════════════════════════════════════════

# SNS Topic for all security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts"
  kms_master_key_id = var.kms_cloudtrail_key_arn # Encrypt SNS messages

  tags = merge(var.tags, {
    Name    = "${var.project_name}-security-alerts"
    Purpose = "SecurityAlerting"
  })
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ─────────────────────────────────────────────────────
# ALARM 1 — ROOT ACCOUNT USAGE
# Root should NEVER be used for day-to-day operations
# Any root login = immediate alert
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${var.project_name}-root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.3
  pattern = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  alarm_description   = "CRITICAL: Root account activity detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 60 # Check every 60 seconds
  statistic           = "Sum"
  threshold           = 1 # Fire on ANY root usage
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  ok_actions          = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 2 — IAM POLICY CHANGES
# Someone modified permissions — could be privilege esc
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "${var.project_name}-iam-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.4
  pattern = "{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy)}"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${var.project_name}-iam-policy-changes"
  alarm_description   = "WARNING: IAM policy modification detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 3 — UNAUTHORIZED API CALLS
# AccessDenied spikes = recon or compromised credential
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.project_name}-unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.1
  pattern = "{($.errorCode=\"*UnauthorizedAccess*\") || ($.errorCode=\"AccessDenied\")}"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.project_name}-unauthorized-api-calls"
  alarm_description   = "WARNING: Spike in unauthorized API calls - possible recon"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 10 # Allow some noise, alert on spike
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 4 — SECURITY GROUP CHANGES
# Firewall rule modified — could open attack surface
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "${var.project_name}-security-group-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.10
  pattern = "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}"

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name          = "${var.project_name}-security-group-changes"
  alarm_description   = "WARNING: Security group modification detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 5 — CLOUDTRAIL DISABLED
# Attacker's first move is often disabling audit logs
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_disabled" {
  name           = "${var.project_name}-cloudtrail-disabled"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.5
  pattern = "{($.eventName=StopLogging) || ($.eventName=DeleteTrail) || ($.eventName=UpdateTrail)}"

  metric_transformation {
    name      = "CloudTrailDisabled"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_disabled" {
  alarm_name          = "${var.project_name}-cloudtrail-disabled"
  alarm_description   = "CRITICAL: CloudTrail has been disabled or modified"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailDisabled"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 60 # Detect within 1 minute
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 6 — CONSOLE LOGIN WITHOUT MFA
# MFA bypass = stolen password is enough to breach
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "console_no_mfa" {
  name           = "${var.project_name}-console-login-no-mfa"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.2
  pattern = "{($.eventName=ConsoleLogin) && ($.additionalEventData.MFAUsed !=\"Yes\") && ($.userIdentity.type !=\"AssumedRole\")}"

  metric_transformation {
    name      = "ConsoleLoginNoMFA"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_no_mfa" {
  alarm_name          = "${var.project_name}-console-login-no-mfa"
  alarm_description   = "CRITICAL: Console login without MFA detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginNoMFA"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}

# ─────────────────────────────────────────────────────
# ALARM 7 — S3 BUCKET POLICY CHANGES
# Bucket policy modified = possible data exposure
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "s3_policy_changes" {
  name           = "${var.project_name}-s3-bucket-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # CIS Benchmark 3.8
  pattern = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "${var.project_name}/SecurityMetrics"
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_policy_changes" {
  alarm_name          = "${var.project_name}-s3-bucket-policy-changes"
  alarm_description   = "WARNING: S3 bucket policy or ACL change detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "${var.project_name}/SecurityMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]

  tags = var.tags
}
