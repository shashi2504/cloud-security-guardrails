data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ─────────────────────────────────────────────────────
# DYNAMODB — FINDINGS TABLE
# Stores every failed finding with TTL auto-expiry
# ─────────────────────────────────────────────────────
resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_name}-cspm-findings"
  billing_mode = "PAY_PER_REQUEST"    # No capacity planning needed
  hash_key     = "scan_id"
  range_key    = "finding_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  # GSI — Query by severity across all scans
  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "scan_id"
    projection_type = "ALL"
  }

  # TTL — Auto-delete findings after 90 days
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # SECURITY: Encrypt with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # SECURITY: Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cspm-findings"
    Purpose = "CSPMFindings"
  })
}

# ─────────────────────────────────────────────────────
# DYNAMODB — SCORES TABLE
# Tracks security score over time for trending
# ─────────────────────────────────────────────────────
resource "aws_dynamodb_table" "scores" {
  name         = "${var.project_name}-cspm-scores"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"
  range_key    = "timestamp"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
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

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cspm-scores"
    Purpose = "SecurityScoreTrend"
  })
}

# ─────────────────────────────────────────────────────
# LAMBDA — PROWLER SCANNER
# Runs Prowler on schedule, stores findings
# ─────────────────────────────────────────────────────
data "archive_file" "prowler_scanner" {
  type        = "zip"
  source_dir  = "${path.root}/../../scans/prowler"
  output_path = "${path.module}/prowler_scanner.zip"
}

resource "aws_lambda_function" "prowler_scanner" {
  function_name    = "${var.project_name}-prowler-scanner"
  description      = "Runs Prowler CSPM scans on schedule"
  filename         = data.archive_file.prowler_scanner.output_path
  source_code_hash = data.archive_file.prowler_scanner.output_base64sha256
  role             = aws_iam_role.prowler_lambda.arn
  handler          = "prowler_scanner.lambda_handler"
  runtime          = "python3.12"

  # Prowler scans take time — generous timeout
  timeout     = 900     # 15 minutes
  memory_size = 1024    # Prowler needs headroom

  environment {
    variables = {
      RESULTS_BUCKET = var.logging_bucket_name
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
      SCORE_TABLE    = aws_dynamodb_table.scores.name
      SNS_TOPIC_ARN  = var.sns_topic_arn
      PROJECT_NAME   = var.project_name
    }
  }

  # SECURITY: Run inside VPC
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.prowler_lambda.id]
  }

  # SECURITY: Encrypt environment variables
  kms_key_arn = var.kms_key_arn

  # SECURITY: No public URL
  # Triggered only by EventBridge

  layers = [aws_lambda_layer_version.prowler.arn]

  tags = merge(var.tags, {
    Name    = "${var.project_name}-prowler-scanner"
    Purpose = "CSPMScanning"
  })
}

# Lambda Layer — Prowler + dependencies
resource "aws_lambda_layer_version" "prowler" {
  layer_name          = "${var.project_name}-prowler-deps"
  description         = "Prowler CSPM tool and dependencies"
  compatible_runtimes = ["python3.12"]
  filename            = "${path.module}/prowler_layer.zip"

  # Build layer with: pip install prowler -t python/
  # zip -r prowler_layer.zip python/
}

# Lambda Security Group — no inbound, outbound to AWS APIs
resource "aws_security_group" "prowler_lambda" {
  name        = "${var.project_name}-prowler-lambda-sg"
  description = "Prowler Lambda: no inbound, HTTPS outbound only"
  vpc_id      = var.vpc_id

  # Outbound to AWS APIs via VPC endpoints
  egress {
    description = "HTTPS to AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-prowler-lambda-sg"
  })
}

# ─────────────────────────────────────────────────────
# IAM — PROWLER LAMBDA ROLE
# Read-only scan + write to DynamoDB/S3/SNS
# ─────────────────────────────────────────────────────
resource "aws_iam_role" "prowler_lambda" {
  name        = "${var.project_name}-prowler-lambda-role"
  description = "Prowler Lambda execution role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

# AWS managed SecurityAudit for read-only scan access
resource "aws_iam_role_policy_attachment" "prowler_security_audit" {
  role       = aws_iam_role.prowler_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_view_only" {
  role       = aws_iam_role.prowler_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "prowler_lambda_custom" {
  name = "${var.project_name}-prowler-lambda-policy"
  role = aws_iam_role.prowler_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Lambda VPC networking
      {
        Sid    = "LambdaVPCAccess"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },

      # Write findings to DynamoDB
      {
        Sid    = "DynamoDBWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          aws_dynamodb_table.scores.arn,
          "${aws_dynamodb_table.findings.arn}/index/*"
        ]
      },

      # Upload reports to S3
      {
        Sid    = "S3ReportsWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${var.logging_bucket_arn}/prowler-reports/*"
      },

      # Publish alerts to SNS
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.sns_topic_arn
      },

      # Lambda logs
      {
        Sid    = "LambdaLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}-prowler-scanner:*"
      },

      # KMS for DynamoDB + Lambda env vars
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = var.kms_key_arn
      },

      # Prowler extra checks (same as IAM module audit role)
      {
        Sid    = "ProwlerExtraChecks"
        Effect = "Allow"
        Action = [
          "account:Get*",
          "ec2:GetEbsEncryptionByDefault",
          "lambda:GetPolicy",
          "lambda:List*",
          "s3:GetAccountPublicAccessBlock",
          "support:Describe*",
          "tag:GetTagKeys"
        ]
        Resource = "*"
      }
    ]
  })
}

# ─────────────────────────────────────────────────────
# EVENTBRIDGE — SCAN SCHEDULE
# Triggers Prowler daily at 2AM UTC
# Off-peak to avoid any impact on production traffic
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${var.project_name}-daily-cspm-scan"
  description         = "Triggers Prowler CSPM scan daily at 2AM UTC"
  schedule_expression = "cron(0 2 * * ? *)"    # 2:00 AM UTC daily

  tags = merge(var.tags, {
    Name    = "${var.project_name}-daily-cspm-scan"
    Purpose = "CSPMSchedule"
  })
}

resource "aws_cloudwatch_event_target" "prowler_lambda" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "ProwlerScanner"
  arn       = aws_lambda_function.prowler_scanner.arn

  # Pass scan context to Lambda
  input = jsonencode({
    source    = "scheduled"
    trigger   = "eventbridge-daily"
    project   = var.project_name
  })
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.prowler_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}

# ─────────────────────────────────────────────────────
# CLOUDWATCH DASHBOARD — CSPM METRICS
# Live security posture visibility
# ─────────────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "cspm" {
  dashboard_name = "${var.project_name}-security-posture"

  dashboard_body = jsonencode({
    widgets = [

      # Security Score
      {
        type   = "metric"
        x      = 0 
        y = 0
        width = 6
        height = 6
        properties = {
          title  = "Security Score (Latest)"
          view   = "singleValue"
          metrics = [[
            "${var.project_name}/CSPM",
            "SecurityScore",
            { stat = "Average", period = 86400 }
          ]]
        }
      },

      # Critical Findings Count
      {
        type   = "metric"
        x      = 6
        y = 0
        width = 6
        height = 6
        properties = {
          title  = "Critical Findings"
          view   = "singleValue"
          metrics = [[
            "${var.project_name}/CSPM",
            "CriticalFindings",
            { stat = "Maximum", period = 86400, color = "#d13212" }
          ]]
        }
      },

      # Score Trend Over Time
      {
        type   = "metric"
        x      = 0
        y = 6
        width = 12
        height = 6
        properties = {
          title  = "Security Score Trend (30 days)"
          view   = "timeSeries"
          metrics = [[
            "${var.project_name}/CSPM",
            "SecurityScore",
            { stat = "Average", period = 86400 }
          ]]
          yAxis = { left = { min = 0, max = 100 } }
        }
      },

      # Findings by Severity
      {
        type   = "metric"
        x      = 12
        y = 0
        width = 12
        height = 6
        properties = {
          title  = "Findings by Severity (Daily)"
          view   = "timeSeries"
          metrics = [
            ["${var.project_name}/CSPM", "CriticalFindings",
              { stat = "Maximum", period = 86400, color = "#d13212", label = "Critical" }],
            ["${var.project_name}/CSPM", "HighFindings",
              { stat = "Maximum", period = 86400, color = "#ff9900", label = "High" }],
            ["${var.project_name}/CSPM", "MediumFindings",
              { stat = "Maximum", period = 86400, color = "#dfb52c", label = "Medium" }]
          ]
        }
      }
    ]
  })
}
