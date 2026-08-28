# ==========================================================
# INTENTIONALLY INSECURE INFRASTRUCTURE
# Purpose: validation target for tfsec / Checkov / OPA / Prowler
# Never store real data here. Destroy when not in use.
# ==========================================================

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------- FLAW 1: publicly readable S3 bucket ----------
# Also: no versioning, no access logging, no explicit encryption config
resource "aws_s3_bucket" "public_data" {
  bucket        = "csg-vulnerable-public-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadOnly"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_data.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_data]
}

# ---------- FLAW 2: SSH open to the internet ----------
resource "aws_security_group" "wide_open" {
  name        = "csg-vulnerable-open-ssh"
  description = "Intentionally insecure: unrestricted SSH ingress"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------- FLAW 3: unencrypted EBS volume ----------
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = false
}

# ---------- FLAW 4: wildcard IAM policy ----------
# Created but deliberately left unattached — inert, still detected
resource "aws_iam_policy" "overly_permissive" {
  name        = "csg-vulnerable-admin-policy"
  description = "Intentionally insecure: full wildcard permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
