data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ─────────────────────────────────────────────────────
# AUDIT TABLE
# Immutable remediation history — 7 year retention
# ─────────────────────────────────────────────────────
resource "aws_dynamodb_table" "audit" {
  name         = "${var.project_name}-remediation-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"
  range_key    = "timestamp"

  attribute {
    name = "event_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "resource_id"
    type = "S"
  }

  # GSI — query all remediations for a specific resource
  global_secondary_index {
    name            = "resource-index"
    hash_key        = "resource_id"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-remediation-audit"
    Purpose = "RemediationAudit"
  })
}

# ─────────────────────────────────────────────────────
# REMEDIATION ENGINE LAMBDA
# ─────────────────────────────────────────────────────
data "archive_file" "remediation_engine" {
  type        = "zip"
  source_dir  = "${path.root}/../../remediation/lambda"
  output_path = "${path.module}/remediation_engine.zip"
}

resource "aws_lambda_function" "remediation_engine" {
  function_name    = "${var.project_name}-remediation-engine"
  description      = "Auto-remediates S3, SG, CloudTrail, IAM violations"
  filename         = data.archive_file.remediation_engine.output_path
  source_code_hash = data.archive_file.remediation_engine.output_base64sha256
  role             = var.lambda_remediation_role_arn
  handler          = "remediation_engine.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 256
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = {
      PROJECT_NAME  = var.project_name
      SNS_TOPIC_ARN = var.sns_topic_arn
      AUDIT_TABLE   = aws_dynamodb_table.audit.name
      ENVIRONMENT   = var.environment
      # SECURITY: Set to "true" to test without making changes
      DRY_RUN       = var.dry_run ? "true" : "false"
    }
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-remediation-engine"
    Purpose = "AutoRemediation"
  })
}

# ─────────────────────────────────────────────────────
# EVENTBRIDGE RULES
# One rule per violation category
# All target the same Lambda — engine routes internally
# ─────────────────────────────────────────────────────

# ── S3 Violations ───────────────────────────────────
resource "aws_cloudwatch_event_rule" "s3_violations" {
  name        = "${var.project_name}-s3-violations"
  description = "Detect S3 public access violations via CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock"
      ]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-s3-violations"
  })
}

resource "aws_cloudwatch_event_target" "s3_remediation" {
  rule      = aws_cloudwatch_event_rule.s3_violations.name
  target_id = "S3RemediationEngine"
  arn       = aws_lambda_function.remediation_engine.arn
}

resource "aws_lambda_permission" "eventbridge_s3" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_violations.arn
}

# ── Security Group Violations ────────────────────────
resource "aws_cloudwatch_event_rule" "sg_violations" {
  name        = "${var.project_name}-sg-violations"
  description = "Detect security group open ingress violations"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "CreateSecurityGroup"
      ]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-sg-violations"
  })
}

resource "aws_cloudwatch_event_target" "sg_remediation" {
  rule      = aws_cloudwatch_event_rule.sg_violations.name
  target_id = "SGRemediationEngine"
  arn       = aws_lambda_function.remediation_engine.arn
}

resource "aws_lambda_permission" "eventbridge_sg" {
  statement_id  = "AllowEventBridgeSG"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_violations.arn
}

# ── CloudTrail Violations ────────────────────────────
resource "aws_cloudwatch_event_rule" "cloudtrail_violations" {
  name        = "${var.project_name}-cloudtrail-violations"
  description = "Detect CloudTrail tampering — highest priority"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail"
      ]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-cloudtrail-violations"
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_remediation" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_violations.name
  target_id = "CloudTrailRemediationEngine"
  arn       = aws_lambda_function.remediation_engine.arn
}

resource "aws_lambda_permission" "eventbridge_cloudtrail" {
  statement_id  = "AllowEventBridgeCloudTrail"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail_violations.arn
}

# ── IAM Violations ───────────────────────────────────
resource "aws_cloudwatch_event_rule" "iam_violations" {
  name        = "${var.project_name}-iam-violations"
  description = "Detect dangerous IAM changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = [
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateAccessKey",
        "AttachRolePolicy"
      ]
    }
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-iam-violations"
  })
}

resource "aws_cloudwatch_event_target" "iam_remediation" {
  rule      = aws_cloudwatch_event_rule.iam_violations.name
  target_id = "IAMRemediationEngine"
  arn       = aws_lambda_function.remediation_engine.arn
}

resource "aws_lambda_permission" "eventbridge_iam" {
  statement_id  = "AllowEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_violations.arn
}

# ─────────────────────────────────────────────────────
# AUDIT TABLE WRITE PERMISSION
# Remediation Lambda needs to write audit records
# ─────────────────────────────────────────────────────
resource "aws_iam_role_policy" "audit_write" {
  name = "${var.project_name}-remediation-audit-write"
  role = split("/", var.lambda_remediation_role_arn)[1]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AuditTableWrite"
      Effect = "Allow"
      Action = [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ]
      Resource = [
        aws_dynamodb_table.audit.arn,
        "${aws_dynamodb_table.audit.arn}/index/*"
      ]
    }]
  })
}
