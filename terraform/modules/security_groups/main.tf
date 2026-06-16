# ─────────────────────────────────────────────────────
# ALB SECURITY GROUP
# Accepts HTTPS from internet, HTTP blocked entirely
# ─────────────────────────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "ALB: HTTPS inbound only, all outbound to app tier"
  vpc_id      = var.vpc_id

  # SECURITY: HTTPS only — HTTP is not allowed
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SECURITY: Outbound only to app SG on app port
  # This is wired after app SG is created (see below)

  # SECURITY: No HTTP ingress — forces encryption in transit
  # Port 80 intentionally omitted

  tags = merge(var.tags, {
    Name = "${var.project_name}-alb-sg"
    Tier = "LoadBalancer"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ─────────────────────────────────────────────────────
# APPLICATION SECURITY GROUP
# Only accepts traffic from ALB — never from internet
# ─────────────────────────────────────────────────────
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "App tier: inbound from ALB only"
  vpc_id      = var.vpc_id

  # SECURITY: Only ALB can reach app tier
  ingress {
    description     = "App port from ALB only"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-app-sg"
    Tier = "Application"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# App → internet for AWS APIs, package updates (via NAT)
resource "aws_security_group_rule" "app_outbound_https" {
  type              = "egress"
  description       = "App HTTPS outbound for AWS APIs via NAT"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.app.id
  cidr_blocks       = ["0.0.0.0/0"]
}


# ─────────────────────────────────────────────────────
# DATABASE SECURITY GROUP
# Only accepts traffic from App SG — completely isolated
# ─────────────────────────────────────────────────────
resource "aws_security_group" "database" {
  name        = "${var.project_name}-database-sg"
  description = "DB tier: inbound from app SG only, no outbound"
  vpc_id      = var.vpc_id

  # SECURITY: Only app tier can query the database
  ingress {
    description     = "DB port from app tier only"
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # SECURITY: No egress rule = no outbound traffic from DB
  # Databases should never initiate connections outbound

  tags = merge(var.tags, {
    Name = "${var.project_name}-database-sg"
    Tier = "Database"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ─────────────────────────────────────────────────────
# BASTION / JUMP HOST SECURITY GROUP
# Emergency access only — locked to specific IP
# SECURITY: This is NOT open to 0.0.0.0/0
# ─────────────────────────────────────────────────────
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Bastion: SSH from approved IPs only"
  vpc_id      = var.vpc_id

  # SECURITY: SSH locked to your corporate/home IP only
  # var.allowed_ssh_cidrs must NEVER contain 0.0.0.0/0
  ingress {
    description = "SSH from approved IPs only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # Bastion needs outbound to reach private instances
  egress {
    description = "SSH to private subnets"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-bastion-sg"
    Tier = "Bastion"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ─────────────────────────────────────────────────────
# VPC ENDPOINTS SECURITY GROUP
# Allows AWS service traffic without hitting internet
# SSM, S3, ECR, Secrets Manager all use this
# ─────────────────────────────────────────────────────
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project_name}-vpc-endpoints-sg"
  description = "VPC Endpoints: HTTPS from within VPC only"
  vpc_id      = var.vpc_id

  # SECURITY: Only internal VPC CIDR can use endpoints
  ingress {
    description = "HTTPS from VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-vpc-endpoints-sg"
    Tier = "VPCEndpoints"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ─────────────────────────────────────────────────────
# ALB → APP RULE (wired separately to avoid circular dep)
# ─────────────────────────────────────────────────────
resource "aws_security_group_rule" "alb_to_app_egress" {
  type                     = "egress"
  description              = "ALB outbound to app tier only"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.app.id
}

# ─────────────────────────────────────────────────────
# APP → DB RULE
# ─────────────────────────────────────────────────────
resource "aws_security_group_rule" "app_to_db_egress" {
  type                     = "egress"
  description              = "App outbound to DB tier only"
  from_port                = var.db_port
  to_port                  = var.db_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.database.id
}
