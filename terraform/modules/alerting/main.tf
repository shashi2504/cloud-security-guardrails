data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
}

# ─────────────────────────────────────────────────────
# SLACK WEBHOOK SECRET
# Stored in Secrets Manager — never in Terraform state
# ─────────────────────────────────────────────────────
resource "aws_secretsmanager_secret" "slack_webhook" {
  name        = "${var.project_name}/slack-webhook"
  description = "Slack webhook URL for security alerts"
  kms_key_id  = var.kms_secrets_key_arn

  tags = merge(var.tags, {
    Name    = "${var.project_name}-slack-webhook"
    Purpose = "Alerting"
  })
}

# Placeholder — set real value with:
# aws secretsmanager put-secret-value \
#   --secret-id cloud-sec-guardrails/slack-webhook \
#   --secret-string '{"slack_webhook_url":"https://hooks.slack.com/..."}'
resource "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id     = aws_secretsmanager_secret.slack_webhook.id
  secret_string = jsonencode({
    slack_webhook_url = "PLACEHOLDER — update via AWS Console or CLI"
  })

  lifecycle {
    ignore_changes = [secret_string]    # Don't overwrite real value on re-apply
  }
}

# ─────────────────────────────────────────────────────
# DEDUP TABLE
# DynamoDB table for alert deduplication
# ─────────────────────────────────────────────────────
resource "aws_dynamodb_table" "alert_dedup" {
  name         = "${var.project_name}-alert-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_hash"

  attribute {
    name = "alert_hash"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-alert-dedup"
    Purpose = "AlertDeduplication"
  })
}

# ─────────────────────────────────────────────────────
# ALERT ROUTER LAMBDA
# ─────────────────────────────────────────────────────
data "archive_file" "alert_router" {
  type        = "zip"
  source_dir  = "${path.root}/../../remediation/lambda"
  output_path = "${path.module}/alert_router.zip"
}

resource "aws_lambda_function" "alert_router" {
  function_name    = "${var.project_name}-alert-router"
  description      = "Routes security alerts to Slack, email, PagerDuty"
  filename         = data.archive_file.alert_router.output_path
  source_code_hash = data.archive_file.alert_router.output_base64sha256
  role             = aws_iam_role.alert_router.arn
  handler          = "alert_router.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = {
      PROJECT_NAME      = var.project_name
      ENVIRONMENT       = var.environment
      SLACK_SECRET_ARN  = aws_secretsmanager_secret.slack_webhook.arn
      ALERT_EMAIL_FROM  = var.alert_email_from
      EMAIL_CRITICAL_TO = var.email_critical_to
      EMAIL_TEAM_TO     = var.email_team_to
      AGGREGATOR_TABLE  = aws_dynamodb_table.alert_dedup.name
      SES_CONFIG_SET    = aws_ses_configuration_set.alerts.name
    }
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-alert-router"
    Purpose = "AlertRouting"
  })
}

# ── Subscribe Lambda to SNS security alerts topic ───
resource "aws_sns_topic_subscription" "alert_router" {
  topic_arn = var.sns_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.alert_router.arn
}

resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert_router.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.sns_topic_arn
}

# ─────────────────────────────────────────────────────
# SES — EMAIL SENDING
# ─────────────────────────────────────────────────────
resource "aws_ses_configuration_set" "alerts" {
  name = "${var.project_name}-security-alerts"

  delivery_options {
    tls_policy = "Require"    # SECURITY: TLS mandatory for email
  }
}

# Verify sending domain — must do this in SES console too
resource "aws_ses_domain_identity" "alerts" {
  domain = var.alert_email_domain
}

resource "aws_ses_domain_dkim" "alerts" {
  domain = aws_ses_domain_identity.alerts.domain
}

# ─────────────────────────────────────────────────────
# IAM — ALERT ROUTER ROLE
# ─────────────────────────────────────────────────────
resource "aws_iam_role" "alert_router" {
  name = "${var.project_name}-alert-router-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "alert_router" {
  name = "${var.project_name}-alert-router-policy"
  role = aws_iam_role.alert_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Lambda logs
      {
        Sid    = "LambdaLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}-alert-router:*"
      },

      # Read Slack webhook from Secrets Manager
      {
        Sid      = "GetSlackSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.slack_webhook.arn
      },

      # Send email via SES
      {
        Sid      = "SESendEmail"
        Effect   = "Allow"
        Action   = "ses:SendEmail"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = var.alert_email_from
          }
        }
      },

      # DynamoDB dedup table
      {
        Sid    = "DynamoDBDedup"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.alert_dedup.arn
      },

      # KMS for Secrets Manager + DynamoDB
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = [var.kms_key_arn, var.kms_secrets_key_arn]
      }
    ]
  })
}
