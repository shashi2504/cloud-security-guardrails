# ─────────────────────────────────────────────────────
# DATA SOURCES
# ─────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ═════════════════════════════════════════════════════
# ROLE 1 — EC2 INSTANCE ROLE
# What EC2 instances are allowed to do
# No SSH needed — SSM Session Manager handles access
# ═════════════════════════════════════════════════════
resource "aws_iam_role" "ec2_instance" {
  name        = "${var.project_name}-ec2-instance-role"
  description = "EC2 instance role - SSM access, secrets read, logs write"

  # Only EC2 service can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEC2AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-ec2-instance-role"
    Purpose = "EC2InstanceProfile"
  })
}

# ── SSM Session Manager (replaces SSH entirely) ────
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ── EC2 Custom Policy — scoped to exact resources ──
resource "aws_iam_role_policy" "ec2_custom" {
  name = "${var.project_name}-ec2-custom-policy"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Read secrets — scoped to this project only
      {
        Sid    = "ReadProjectSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.project_name}/*"
      },

      # KMS decrypt — only for secrets & EBS keys
      {
        Sid    = "KMSDecryptForSecrets"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          var.kms_ebs_key_arn,
          var.kms_secrets_key_arn
        ]
      },

      # Write app logs to CloudWatch
      {
        Sid    = "WriteAppLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/app/${var.project_name}/*"
      },

      # Read own instance metadata (tags, etc.)
      {
        Sid    = "DescribeOwnInstance"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },

      # SECURITY: Explicit deny — EC2 cannot touch IAM
      {
        Sid      = "DenyIAMAccess"
        Effect   = "Deny"
        Action   = "iam:*"
        Resource = "*"
      },

      # SECURITY: EC2 cannot modify its own security groups
      {
        Sid    = "DenySecurityGroupModification"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Instance Profile — attaches role to EC2 ───────
resource "aws_iam_instance_profile" "ec2" {
  name = "${var.project_name}-ec2-instance-profile"
  role = aws_iam_role.ec2_instance.name

  tags = var.tags
}

# ═════════════════════════════════════════════════════
# ROLE 2 — CLOUDTRAIL ROLE
# Allows CloudTrail to write logs to CloudWatch
# S3 access is handled via bucket policy (Module 4)
# ═════════════════════════════════════════════════════
resource "aws_iam_role" "cloudtrail" {
  name        = "${var.project_name}-cloudtrail-role"
  description = "CloudTrail role - write logs to CloudWatch only"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudTrailAssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      # SECURITY: Only from this account
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = local.account_id
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cloudtrail-role"
    Purpose = "CloudTrailLogging"
  })
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "${var.project_name}-cloudtrail-policy"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Write logs to CloudWatch — scoped to trail log group
      {
        Sid    = "WriteCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:aws-cloudtrail-logs-${var.project_name}:*"
      },

      # KMS — encrypt log data in CloudWatch
      {
        Sid    = "KMSForCloudTrailLogs"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = var.kms_cloudtrail_key_arn
      }
    ]
  })
}

# ═════════════════════════════════════════════════════
# ROLE 3 — LAMBDA REMEDIATION ROLE
# Used in Phase 6 — auto-fixes misconfigurations
# Scoped tightly: fix S3, fix SGs, fix CloudTrail only
# ═════════════════════════════════════════════════════
resource "aws_iam_role" "lambda_remediation" {
  name        = "${var.project_name}-lambda-remediation-role"
  description = "Lambda role - auto-remediate S3, SG, CloudTrail issues"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowLambdaAssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-lambda-remediation-role"
    Purpose = "AutoRemediation"
  })
}

resource "aws_iam_role_policy" "lambda_remediation" {
  name = "${var.project_name}-lambda-remediation-policy"
  role = aws_iam_role.lambda_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Lambda basic execution — write its own logs
      {
        Sid    = "LambdaBasicExecution"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}-remediation-*"
      },

      # Fix public S3 buckets — block public access
      {
        Sid    = "RemediateS3PublicAccess"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      },

      # Fix open security groups — remove bad rules
      {
        Sid    = "RemediateSecurityGroups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeSecurityGroupRules"
        ]
        Resource = "*"
      },

      # Re-enable CloudTrail if disabled
      {
        Sid    = "RemediateCloudTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:StartLogging",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/*"
      },

      # Publish remediation alerts to SNS
      {
        Sid      = "PublishRemediationAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${local.region}:${local.account_id}:${var.project_name}-security-alerts"
      },

      # SECURITY: Lambda cannot create or modify IAM
      {
        Sid    = "DenyIAMModification"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:CreateUser",
          "iam:DeleteUser"
        ]
        Resource = "*"
      }
    ]
  })
}

# ═════════════════════════════════════════════════════
# ROLE 4 — SECURITY AUDIT ROLE
# Read-only role for Prowler CSPM scanning (Phase 3)
# Uses AWS managed SecurityAudit + ViewOnlyAccess
# ═════════════════════════════════════════════════════
resource "aws_iam_role" "security_audit" {
  name        = "${var.project_name}-security-audit-role"
  description = "Read-only security audit role for Prowler CSPM"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowAssumeForAudit"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${local.account_id}:root"
      }
      Action = "sts:AssumeRole"
      # SECURITY: Require MFA to assume audit role
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name    = "${var.project_name}-security-audit-role"
    Purpose = "CSPMScanning"
  })
}

# AWS managed read-only policies — battle-tested scope
resource "aws_iam_role_policy_attachment" "security_audit_policy" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "security_view_only" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Extra permissions Prowler needs beyond managed policies
resource "aws_iam_role_policy" "security_audit_extra" {
  name = "${var.project_name}-security-audit-extra"
  role = aws_iam_role.security_audit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Prowler-specific checks
      {
        Sid    = "ProwlerExtraChecks"
        Effect = "Allow"
        Action = [
          "account:Get*",
          "appstream:Describe*",
          "codeartifact:List*",
          "cognito-idp:ListUserPools",
          "ds:Describe*",
          "ds:List*",
          "ec2:GetEbsEncryptionByDefault",
          "ecr:Describe*",
          "lambda:GetPolicy",
          "lambda:List*",
          "macie2:GetMacieSession",
          "s3:GetAccountPublicAccessBlock",
          "shield:Describe*",
          "shield:List*",
          "ssm:Describe*",
          "support:Describe*",
          "tag:GetTagKeys",
          "wellarchitected:List*"
        ]
        Resource = "*"
      },

      # SECURITY: Explicit deny on any write operations
      {
        Sid    = "DenyAllWrite"
        Effect = "Deny"
        Action = [
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Update*",
          "ec2:Create*",
          "ec2:Delete*",
          "ec2:Modify*",
          "s3:Put*",
          "s3:Delete*"
        ]
        Resource = "*"
      }
    ]
  })
}

# ═════════════════════════════════════════════════════
# ROLE 5 — CI/CD DEPLOYMENT ROLE
# GitHub Actions assumes this role via OIDC
# No long-lived credentials — token-based auth only
# ═════════════════════════════════════════════════════

# OIDC Provider for GitHub Actions
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # GitHub Actions OIDC thumbprint
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]

  tags = merge(var.tags, {
    Name    = "github-actions-oidc"
    Purpose = "CICDDeployment"
  })
}

resource "aws_iam_role" "cicd_deployment" {
  name        = "${var.project_name}-cicd-deployment-role"
  description = "GitHub Actions OIDC role - Terraform deployment"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowGitHubActionsOIDC"
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github_actions.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # SECURITY: Only your repo can assume this role
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })

  # SECURITY: Permission boundary caps maximum permissions
  # Even if policy is misconfigured, boundary limits blast radius
  permissions_boundary = aws_iam_policy.cicd_permission_boundary.arn

  tags = merge(var.tags, {
    Name    = "${var.project_name}-cicd-deployment-role"
    Purpose = "TerraformDeployment"
  })
}

# Permission boundary — hard ceiling on what CI/CD can do
resource "aws_iam_policy" "cicd_permission_boundary" {
  name        = "${var.project_name}-cicd-permission-boundary"
  description = "Hard ceiling on CI/CD role permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Allow Terraform state operations
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-terraform-state",
          "arn:aws:s3:::${var.project_name}-terraform-state/*"
        ]
      },

      # DynamoDB for Terraform state locking
      {
        Sid    = "TerraformStateLocking"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.project_name}-terraform-locks"
      },

      # Allow deploying project resources
      {
        Sid    = "AllowProjectResourceDeployment"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "iam:GetRole",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "cloudtrail:*",
          "logs:*",
          "lambda:*",
          "sns:*",
          "events:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
        }
      },

      # SECURITY: CI/CD can NEVER touch billing or org settings
      {
        Sid    = "DenyDangerousActions"
        Effect = "Deny"
        Action = [
          "organizations:*",
          "account:CloseAccount",
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "iam:UpdateAccountPasswordPolicy",
          "sts:AssumeRole" # Cannot pivot to other roles
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "cicd_deployment" {
  name = "${var.project_name}-cicd-deployment-policy"
  role = aws_iam_role.cicd_deployment.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformDeployPermissions"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "iam:GetRole",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetInstanceProfile",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PassRole",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:CreateOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "kms:*",
          "cloudtrail:*",
          "logs:*",
          "lambda:*",
          "sns:*",
          "events:*",
          "config:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = local.region
          }
        }
      }
    ]
  })
}
