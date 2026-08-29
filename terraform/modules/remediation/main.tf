# Auto-remediation for public S3 buckets and internet-facing admin ports.
#
# Defaults to dry-run. Enforcement requires setting enforce = true
# explicitly, and even then the handler refuses to act on any resource
# without AutoRemediate=enabled and Project=cloud-security-guardrails.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# output_file_mode fixes the permission bits in the archive. Without it the
# zip hash depends on local file mode and mtime, so a plan run on a fresh
# clone reports a change to the function on every run — noise that trains
# people to ignore plan output.
data "archive_file" "handler" {
  type             = "zip"
  source_file      = "${var.source_dir}/handler.py"
  output_path      = "${path.module}/.build/handler.zip"
  output_file_mode = "0644"
}

resource "aws_iam_role" "this" {
  name = var.name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Four write actions, nothing more. Read actions are needed to evaluate the
# tag gate before acting.
#
# ec2:RevokeSecurityGroupIngress is restricted by resource tag in IAM.
# s3:PutPublicAccessBlock is not: S3 does not support tag-based conditions
# on that action, so the tag gate for buckets is enforced in the handler
# instead. Worth knowing which of the two controls is defence-in-depth and
# which is the only control.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "this" {
  name = var.name
  role = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadForTagEvaluation"
        Effect = "Allow"
        Action = [
          "s3:GetBucketTagging",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "ec2:DescribeSecurityGroups",
        ]
        Resource = "*"
      },
      {
        Sid      = "RemediateBuckets"
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging"]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::*"
      },
      {
        Sid      = "RemediateTaggedSecurityGroups"
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupIngress", "ec2:CreateTags"]
        Resource = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:security-group/*"

        Condition = {
          StringEquals = {
            "aws:ResourceTag/AutoRemediate" = "enabled"
            "aws:ResourceTag/Project"       = "cloud-security-guardrails"
          }
        }
      },
      {
        Sid      = "Logging"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.this.arn}:*"
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        # The topic is KMS-encrypted, so publishing needs key access too.
        Sid      = "EncryptAlerts"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "this" {
  function_name = var.name
  role          = aws_iam_role.this.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = 30

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  environment {
    variables = {
      ENFORCE       = tostring(var.enforce)
      SNS_TOPIC_ARN = var.sns_topic_arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.this]
}

resource "aws_cloudwatch_event_rule" "this" {
  name        = "${var.name}-trigger"
  description = "CloudTrail events that can expose a bucket or open an admin port"

  event_pattern = jsonencode({
    source        = ["aws.s3", "aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "AuthorizeSecurityGroupIngress",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "this" {
  rule = aws_cloudwatch_event_rule.this.name
  arn  = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
