# ─────────────────────────────────────────
# VPC
# ─────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true # Needed for SSM, ECR, etc.
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-vpc"
  })
}

# ─────────────────────────────────────────
# INTERNET GATEWAY — Public subnets only
# ─────────────────────────────────────────
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-igw"
  })
}

# ─────────────────────────────────────────
# PUBLIC SUBNETS — 2 AZs for HA
# ─────────────────────────────────────────
resource "aws_subnet" "public" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  # SECURITY: Never auto-assign public IPs
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
    Tier = "Public"
  })
}

# ─────────────────────────────────────────
# PRIVATE SUBNETS — Where workloads live
# ─────────────────────────────────────────
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  # SECURITY: Private subnets never get public IPs
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
    Tier = "Private"
  })
}

# ─────────────────────────────────────────
# ELASTIC IP — For NAT Gateway
# ─────────────────────────────────────────
resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]

  tags = merge(var.tags, {
    Name = "${var.project_name}-nat-eip"
  })
}

# ─────────────────────────────────────────
# NAT GATEWAY — Private subnets reach internet
# Sits in PUBLIC subnet, routes private traffic
# ─────────────────────────────────────────
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id # NAT lives in public subnet

  depends_on = [aws_internet_gateway.main]

  tags = merge(var.tags, {
    Name = "${var.project_name}-nat-gateway"
  })
}

# ─────────────────────────────────────────
# ROUTE TABLE — Public (via Internet Gateway)
# ─────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-public-rt"
  })
}

# ─────────────────────────────────────────
# ROUTE TABLE — Private (via NAT Gateway)
# ─────────────────────────────────────────
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-private-rt"
  })
}

# ─────────────────────────────────────────
# ROUTE TABLE ASSOCIATIONS
# ─────────────────────────────────────────
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ─────────────────────────────────────────
# VPC FLOW LOGS — Capture all network traffic
# SECURITY: Required for threat detection & audit
# ─────────────────────────────────────────
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.vpc_flow_log.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log.arn
  traffic_type    = "ALL" # Capture ACCEPT + REJECT
  vpc_id          = aws_vpc.main.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })
}

resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  name              = "/aws/vpc/flow-logs/${var.project_name}"
  retention_in_days = 90 # SECURITY: 90-day retention for forensics
  kms_key_id        = var.kms_cloudtrail_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "vpc_flow_log" {
  name = "${var.project_name}-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "vpc_flow_log" {
  name = "${var.project_name}-vpc-flow-log-policy"
  role = aws_iam_role.vpc_flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "arn:aws:logs:*:*:log-group:/aws/vpc/flow-logs/${var.project_name}:*"
    }]
  })
}
