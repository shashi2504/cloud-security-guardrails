# GitHub Actions authenticates via OIDC rather than stored access keys.
# Credentials are short-lived and issued per workflow run, so there is
# nothing to rotate and nothing to leak.
#
# Two roles with different trust conditions:
#   plan  — read-only, assumable from pull requests
#   apply — write, assumable only from refs/heads/main
#
# The sub condition is the security boundary. Without the repo:org/repo:
# prefix, any repository on GitHub could assume these roles.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  # AWS validates GitHub's certificate chain against its own trust store for
  # this provider, so the thumbprint is no longer load-bearing. Kept because
  # the API still requires the field.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  # GitHub appends immutable numeric IDs to the org and repo in the OIDC
  # subject claim: repo:owner@<org-id>/repo@<repo-id>:ref:refs/heads/main
  # The IDs pin the claim to this specific repository — a repo recreated
  # under the same name gets a different ID and will not match.
  repo_exact = "${var.github_org}@${var.github_org_id}/${var.github_repo}@${var.github_repo_id}"
  repo_glob  = "${var.github_org}@*/${var.github_repo}@*"
}

data "aws_iam_policy_document" "assume_plan" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Pull requests and pushes to main may plan.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${local.repo_glob}:pull_request",
        "repo:${local.repo_glob}:ref:refs/heads/main",
      ]
    }
  }
}

data "aws_iam_policy_document" "assume_apply" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # main only. A pull request — including one from a fork — cannot match
    # this condition and so cannot obtain write credentials.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo_exact}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name               = "${var.name_prefix}-plan"
  assume_role_policy = data.aws_iam_policy_document.assume_plan.json
}

resource "aws_iam_role" "apply" {
  name               = "${var.name_prefix}-apply"
  assume_role_policy = data.aws_iam_policy_document.assume_apply.json
}

# Read-only across the services this project uses, plus state access.
resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "plan_state" {
  name = "${var.name_prefix}-plan-state"
  role = aws_iam_role.plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      # Read-only. The plan job runs with -lock=false so it never writes a
      # lock object: granting the plan role write access to state would let
      # it overwrite the state file, and whoever controls state controls what
      # the next apply creates or destroys.
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}",
        "arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}/*",
      ]
    }]
  })
}

# The apply role is scoped to the services this project deploys rather than
# given PowerUserAccess. Longer, but PowerUser is the *:* pattern this
# project's own gate blocks, and a deployment role is exactly the kind of
# thing that quietly accumulates permissions if it starts broad.
#
# iam:* is unavoidable — the landing zone creates roles and policies — but
# it is scoped to this account and the role cannot touch users or the
# account's own IAM settings.

# Permissions boundary for every role the pipeline creates.
#
# Without this, iam:PutRolePolicy on role/* is a privilege escalation path:
# the apply role could create a role granting *:*, attach it, and pass it to
# a Lambda. Checkov's CKV_AWS_286 and CKV_AWS_289 flagged exactly that, and
# they were right.
#
# A boundary caps effective permissions at the intersection of the role's
# own policy and this document, so a role created by the pipeline cannot
# exceed these limits regardless of what policy is attached to it.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_policy" "pipeline_boundary" {
  # checkov:skip=CKV_AWS_286:A permissions boundary is a ceiling, not a grant. Broad actions here cap what a role may do; they confer nothing.
  # checkov:skip=CKV_AWS_289:As above — boundary semantics, not an identity policy.
  name        = "${var.name_prefix}-boundary"
  description = "Ceiling on any role created by the deployment pipeline"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ServiceOperations"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "kms:*",
          "cloudtrail:*",
          "logs:*",
          "lambda:*",
          "events:*",
          "tag:*",
        ]
        Resource = "*"
      },
      {
        Sid    = "NoIdentityManipulation"
        Effect = "Deny"
        Action = [
          "iam:*",
          "organizations:*",
          "account:*",
          "sts:AssumeRole",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "apply" {
  # checkov:skip=CKV_AWS_286:Escalation is blocked by the iam:PermissionsBoundary condition on ManageServiceRoles. Checkov evaluates only policy/Statement/[0]/Action — it never reads the Condition block.
  # checkov:skip=CKV_AWS_289:As above — the boundary condition constrains every role this policy can create or modify.
  name = "${var.name_prefix}-apply"
  role = aws_iam_role.apply.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DeployLandingZone"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "kms:*",
          "cloudtrail:*",
          "logs:*",
          "lambda:*",
          "events:*",
          "tag:*",
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageServiceRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"

        # Every role this pipeline creates or modifies must carry the
        # boundary. Without the condition the actions above are an
        # escalation path.
        Condition = {
          StringEquals = {
            "iam:PermissionsBoundary" = aws_iam_policy.pipeline_boundary.arn
          }
        }
      },
      {
        # Actions that do not accept the PermissionsBoundary condition key.
        # Read-only plus PassRole, scoped to roles under this project.
        Sid    = "RoleReadAndPass"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListRoleTags",
          "iam:PassRole",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"
      },
      {
        Sid    = "ReadForPlan"
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:GetOpenIDConnectProvider",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
      {
        # The deployment role must not be able to create IAM users, mint
        # access keys, or alter account-level settings. Explicit deny beats
        # relying on the absence of an allow.
        Sid    = "DenyIdentityAndAccountChanges"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:DeleteUser",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicy",
          "organizations:*",
          "account:*",
        ]
        Resource = "*"
      },
    ]
  })
}

# Prowler's scan role. Replaces the prowler-audit IAM user and its
# long-lived key: the scheduled workflow assumes this instead, so there is
# no stored credential for the CSPM scanner either.
resource "aws_iam_role" "prowler" {
  name               = "${var.name_prefix}-prowler"
  assume_role_policy = data.aws_iam_policy_document.assume_plan.json
}

resource "aws_iam_role_policy_attachment" "prowler_security_audit" {
  role       = aws_iam_role.prowler.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_view_only" {
  role       = aws_iam_role.prowler.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Reads Prowler needs beyond the two managed policies.
#
# Resource: "*" is unavoidable here — these actions operate on the account
# itself, not on a resource ARN, so there is nothing narrower to scope to.
#
# This is an accepted risk rather than a scanner error. The role holds
# SecurityAudit and ViewOnlyAccess, so it can enumerate every resource and
# policy in the account: real reconnaissance value if the trust policy were
# ever widened. It is accepted because a CSPM tool requires account-wide
# read by definition, the role holds no write permission (verified: a
# CreateBucket attempt returns AccessDenied), and assumption is limited to
# workflows in this repository.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "prowler_extra" {
  name = "${var.name_prefix}-prowler-extra"
  role = aws_iam_role.prowler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishFindings"
      Effect   = "Allow"
      Action   = ["sns:Publish", "kms:GenerateDataKey", "kms:Decrypt"]
      Resource = "*"
      }, {
      # PutMetricData does not support resource-level permissions; the
      # namespace condition is the only available scoping.
      Sid      = "EmitScoreMetrics"
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = "*"
      Condition = {
        StringEquals = {
          "cloudwatch:namespace" = "CloudSecurityGuardrails"
        }
      }
      }, {
      Effect = "Allow"
      Action = [
        "account:Get*",
        "ec2:GetEbsEncryptionByDefault",
        "s3:GetAccountPublicAccessBlock",
        "shield:GetSubscriptionState",
        "support:Describe*",
        "tag:GetTagKeys",
      ]
      Resource = "*"
    }]
  })
}
