# Security alerting. Remediation results and CSPM findings publish here.
#
# The topic is KMS-encrypted: alert bodies name the affected resource and
# the finding, which is a map of what is currently wrong in the account.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_sns_topic" "this" {
  name              = var.name
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.this.arn
  protocol  = "email"
  endpoint  = var.email_endpoint
}

# Only principals in this account may publish. Without this the topic
# policy defaults to owner-only, which is correct, but stating it makes the
# boundary explicit and survives someone widening it later.
resource "aws_sns_topic_policy" "this" {
  arn = aws_sns_topic.this.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AccountPublish"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.this.arn
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["sns:Publish"]
        Resource  = aws_sns_topic.this.arn

        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}
