# ─────────────────────────────────────────────────────
# DATA SOURCE
# ─────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ═════════════════════════════════════════════════════
# BUCKET 1 — ACCESS LOGS BUCKET (meta-logger)
# Logs who accessed the main logging bucket
# Must be created FIRST — main bucket references it
# ═════════════════════════════════════════════════════
resource "aws_s3_bucket" "access_logs" {
  bucket        = "${var.project_name}-access-logs-${local.account_id}"
  force_destroy = false # SECURITY: Prevent accidental deletion

  tags = merge(var.tags, {
    Name    = "${var.project_name}-access-logs"
    Purpose = "S3AccessLogging"
  })
}

# ── Block ALL public access ────────────────────────
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Encryption with KMS ────────────────────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_key_arn
    }
    # SECURITY: Reject unencrypted uploads
    bucket_key_enabled = true
  }
}

# ── Versioning ─────────────────────────────────────
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ── Lifecycle — auto-expire old access logs ────────
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {
      prefix = "" # ← matches all objects
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA" # Cheaper after 30 days
    }

    transition {
      days          = 90
      storage_class = "GLACIER" # Archive after 90 days
    }

    expiration {
      days = 365 # Delete after 1 year
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ── Bucket policy — SSL only ───────────────────────
resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  depends_on = [aws_s3_bucket_public_access_block.access_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # SECURITY: Deny any request not using HTTPS
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },

      # SECURITY: Deny unencrypted object uploads
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = ["aws:kms", "AES256"]
          }
          StringNotLike = {
            "aws:PrincipalServiceName" = "logging.s3.amazonaws.com"
          }
        }
      },

      {
        Sid    = "AllowLoggingServiceSSE"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/s3-access-logs/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount"               = local.account_id
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },

      # Allow S3 service to write access logs
      {
        Sid    = "AllowS3AccessLogsWrite"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logs.arn}/s3-access-logs/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# ═════════════════════════════════════════════════════
# BUCKET 2 — MAIN LOGGING BUCKET
# Central log sink for CloudTrail, VPC Flow Logs, ALB
# ═════════════════════════════════════════════════════
resource "aws_s3_bucket" "logging" {
  bucket              = "${var.project_name}-logs-${local.account_id}"
  force_destroy       = false # SECURITY: Prevent accidental deletion
  object_lock_enabled = true
  tags = merge(var.tags, {
    Name    = "${var.project_name}-logs"
    Purpose = "CentralLogging"
  })
}

# ── Block ALL public access — all 4 settings ──────
# SECURITY: This is the most critical S3 control
resource "aws_s3_bucket_public_access_block" "logging" {
  bucket = aws_s3_bucket.logging.id

  block_public_acls       = true # Block new public ACLs
  block_public_policy     = true # Block new public bucket policies
  ignore_public_acls      = true # Ignore existing public ACLs
  restrict_public_buckets = true # Restrict public bucket policies
}

# ── KMS Encryption ─────────────────────────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_s3_key_arn
    }
    bucket_key_enabled = true # Reduces KMS API call costs
  }
}

# ── Versioning — required for Object Lock ─────────
resource "aws_s3_bucket_versioning" "logging" {
  bucket = aws_s3_bucket.logging.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ── Object Lock — tamper-proof logs ───────────────
# SECURITY: Logs cannot be deleted or modified
# Compliance mode: even root cannot delete during retention
resource "aws_s3_bucket_object_lock_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id

  depends_on = [aws_s3_bucket_versioning.logging]

  rule {
    default_retention {
      mode = "COMPLIANCE" # GOVERNANCE = admin can override; COMPLIANCE = nobody can
      days = 90
    }
  }
}

# ── Access Logging → meta-logger bucket ───────────
resource "aws_s3_bucket_logging" "logging" {
  bucket        = aws_s3_bucket.logging.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access-logs/"
}

# ── Lifecycle — tiered storage for cost control ───
resource "aws_s3_bucket_lifecycle_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id

  # CloudTrail logs
  rule {
    id     = "cloudtrail-logs-lifecycle"
    status = "Enabled"

    filter {
      prefix = "cloudtrail/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years — common compliance requirement
    }
  }

  # VPC Flow logs
  rule {
    id     = "vpc-flow-logs-lifecycle"
    status = "Enabled"

    filter {
      prefix = "vpc-flow-logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }

  # ALB access logs
  rule {
    id     = "alb-access-logs-lifecycle"
    status = "Enabled"

    filter {
      prefix = "alb-logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }
}

# ── Bucket Policy ──────────────────────────────────
resource "aws_s3_bucket_policy" "logging" {
  bucket = aws_s3_bucket.logging.id

  depends_on = [aws_s3_bucket_public_access_block.logging]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # SECURITY: Deny HTTP — all traffic must use HTTPS
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.logging.arn,
          "${aws_s3_bucket.logging.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },

      # SECURITY: Deny unencrypted uploads
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logging.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },

      {
        Sid       = "DenyWrongKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logging.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = [
              var.kms_s3_key_arn,        # S3 key — for general uploads
              var.kms_cloudtrail_key_arn # CloudTrail key — for trail logs
            ]
          }
        }
      },

      # Allow CloudTrail to write logs
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logging.arn}/cloudtrail/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },

      # Allow CloudTrail to check bucket ACL
      {
        Sid    = "AllowCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logging.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },

      # Allow ELB/ALB to write access logs
      {
        Sid    = "AllowALBLogsWrite"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logging.arn}/alb-logs/*"
      },

      # SECURITY: Deny cross-account access
      {
        Sid       = "DenyExternalAccountAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.logging.arn,
          "${aws_s3_bucket.logging.arn}/*"
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = local.account_id
          }
          Bool = {
            "aws:PrincipalIsAWSService" = "false"
          }
          # Exempt AWS services (CloudTrail, ALB, etc.)
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::${local.account_id}:root",
              "arn:aws:sts::${local.account_id}:*"
            ]
          }
        }
      }
    ]
  })
}
