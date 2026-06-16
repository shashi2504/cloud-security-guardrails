# ─────────────────────────────────────────────────────
# DATA SOURCE — Current AWS account & region
# Used in key policies to scope access correctly
# ─────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ─────────────────────────────────────────────────────
# S3 KMS KEY
# Used by all S3 buckets in this platform
# ─────────────────────────────────────────────────────
resource "aws_kms_key" "s3" {
  description             = "${var.project_name} - S3 encryption key"
  deletion_window_in_days = 7     # Minimum allowed — prevents accidental loss
  enable_key_rotation     = true  # SECURITY: Auto-rotate every 365 days
  multi_region            = false # Single region — keep it simple & auditable

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # ── Root account has full control ──────────────
      # Without this, the key becomes unmanageable
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── S3 service can use the key ──────────────────
      {
        Sid    = "AllowS3ServiceEncryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },

      # ── IAM roles can use key (encrypt/decrypt only) ─
      # NOT allowed to manage the key itself
      {
        Sid    = "AllowIAMRoleUsage"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },

      # ── DENY key deletion by non-admin ─────────────
      {
        Sid    = "DenyKeyDeletionByNonAdmin"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:root"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-s3-kms-key"
    Purpose = "S3Encryption"
  })
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.project_name}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# ─────────────────────────────────────────────────────
# CLOUDTRAIL KMS KEY
# Separate key for audit logs — isolation is intentional
# If S3 key is compromised, audit logs stay protected
# ─────────────────────────────────────────────────────
resource "aws_kms_key" "cloudtrail" {
  description             = "${var.project_name} - CloudTrail encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # ── Root account full control ───────────────────
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── CloudTrail service MUST be able to encrypt ──
      # Without this, CloudTrail cannot write logs
      {
        Sid    = "AllowCloudTrailEncryption"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/*"
          }
        }
      },

      # ── CloudWatch Logs service can encrypt/decrypt ────
      {
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${local.region}:${local.account_id}:log-group:aws-cloudtrail-logs-*",
              "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/vpc/flow-logs/*"
            ]
          }
        }
      },

      # ── Allow describe for CloudTrail validation ────
      {
        Sid    = "AllowCloudTrailDescribe"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },

      # ── DENY key deletion by non-admin ─────────────
      {
        Sid    = "DenyKeyDeletionByNonAdmin"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:root"
          }
        }
      },

      {
        Sid    = "AllowSNSEncryption"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },

      # ── Security team can decrypt logs for analysis ─
      {
        Sid    = "AllowSecurityTeamDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cloudtrail-kms-key"
    Purpose = "CloudTrailEncryption"
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# ─────────────────────────────────────────────────────
# EBS KMS KEY
# Encrypts EC2 root volumes and data volumes
# ─────────────────────────────────────────────────────
resource "aws_kms_key" "ebs" {
  description             = "${var.project_name} - EBS encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── EC2 service needs to attach encrypted volumes ─
      {
        Sid    = "AllowEC2ServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },

      # ── DENY key deletion by non-admin ─────────────
      {
        Sid    = "DenyKeyDeletionByNonAdmin"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:root"
          }
        }
      },

      # ── Allow EC2 role to use EBS key ───────────────
      {
        Sid    = "AllowEC2RoleUsage"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-ebs-kms-key"
    Purpose = "EBSEncryption"
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.project_name}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# ─────────────────────────────────────────────────────
# RDS KMS KEY
# Encrypts database storage and snapshots
# ─────────────────────────────────────────────────────
resource "aws_kms_key" "rds" {
  description             = "${var.project_name} - RDS encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── DENY key deletion by non-admin ─────────────
      {
        Sid    = "DenyKeyDeletionByNonAdmin"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:root"
          }
        }
      },

      # ── RDS service encrypts storage & snapshots ────
      {
        Sid    = "AllowRDSServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-rds-kms-key"
    Purpose = "RDSEncryption"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.project_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ─────────────────────────────────────────────────────
# SECRETS MANAGER KMS KEY
# Encrypts all secrets — DB passwords, API keys, certs
# ─────────────────────────────────────────────────────
resource "aws_kms_key" "secrets" {
  description             = "${var.project_name} - Secrets Manager encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── DENY key deletion by non-admin ─────────────
      {
        Sid    = "DenyKeyDeletionByNonAdmin"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:root"
          }
        }
      },

      # ── Secrets Manager service encrypts/decrypts ───
      {
        Sid    = "AllowSecretsManagerUsage"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        # SECURITY: Only from this account
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-secrets-kms-key"
    Purpose = "SecretsEncryption"
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.project_name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}
