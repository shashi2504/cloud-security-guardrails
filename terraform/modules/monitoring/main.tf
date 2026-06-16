data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ─────────────────────────────────────────────────────
# METRICS PUBLISHER LAMBDA
# Runs after every Prowler scan — bridges DynamoDB
# scan results into CloudWatch custom metrics
# ─────────────────────────────────────────────────────
data "archive_file" "metrics_publisher" {
  type        = "zip"
  source_file = "${path.root}/../../dashboards/metrics_publisher.py"
  output_path = "${path.module}/metrics_publisher.zip"
}

resource "aws_lambda_function" "metrics_publisher" {
  function_name    = "${var.project_name}-metrics-publisher"
  description      = "Publishes CSPM scan results to CloudWatch metrics"
  filename         = data.archive_file.metrics_publisher.output_path
  source_code_hash = data.archive_file.metrics_publisher.output_base64sha256
  role             = aws_iam_role.metrics_publisher.arn
  handler          = "metrics_publisher.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      PROJECT_NAME   = var.project_name
      FINDINGS_TABLE = var.findings_table_name
      SCORE_TABLE    = var.scores_table_name
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.tags, {
    Name    = "${var.project_name}-metrics-publisher"
    Purpose = "MetricsPublishing"
  })
}

# ── Trigger — fires 5 min after Prowler scan completes ──
resource "aws_cloudwatch_event_rule" "after_scan" {
  name                = "${var.project_name}-after-cspm-scan"
  description         = "Trigger metrics publish 5 min after daily scan"
  schedule_expression = "cron(5 2 * * ? *)"    # 02:05 UTC — after Prowler at 02:00

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "metrics_publisher" {
  rule      = aws_cloudwatch_event_rule.after_scan.name
  target_id = "MetricsPublisher"
  arn       = aws_lambda_function.metrics_publisher.arn
}

resource "aws_lambda_permission" "eventbridge_metrics" {
  statement_id  = "AllowEventBridgeInvokeMetrics"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metrics_publisher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.after_scan.arn
}

# ── IAM Role ────────────────────────────────────────────
resource "aws_iam_role" "metrics_publisher" {
  name = "${var.project_name}-metrics-publisher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "metrics_publisher" {
  name = "${var.project_name}-metrics-publisher-policy"
  role = aws_iam_role.metrics_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # Write CloudWatch metrics
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = [
          "cloudwatch:PutMetricData",
          "cloudwatch:PutMetricAlarm"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "${var.project_name}/SecurityMetrics"
          }
        }
      },

      # Read DynamoDB scan results
      {
        Sid    = "DynamoDBRead"
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:GetItem"
        ]
        Resource = [
          var.findings_table_arn,
          var.scores_table_arn,
          "${var.findings_table_arn}/index/*"
        ]
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
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.project_name}-metrics-publisher:*"
      },

      # KMS decrypt for DynamoDB
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# ─────────────────────────────────────────────────────
# GRAFANA ON ECS FARGATE
# Runs Grafana as a container — no EC2 to manage
# Internal only — accessed via ALB with auth
# ─────────────────────────────────────────────────────
resource "aws_ecs_cluster" "monitoring" {
  name = "${var.project_name}-monitoring"

  setting {
    name  = "containerInsights"
    value = "enabled"    # Full ECS metrics in CloudWatch
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-monitoring"
    Purpose = "GrafanaHosting"
  })
}

resource "aws_ecs_task_definition" "grafana" {
  family                   = "${var.project_name}-grafana"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"     # 0.5 vCPU
  memory                   = "1024"    # 1 GB
  execution_role_arn       = aws_iam_role.grafana_execution.arn
  task_role_arn            = aws_iam_role.grafana_task.arn

  container_definitions = jsonencode([{
    name  = "grafana"
    image = "grafana/grafana:10.2.0"

    portMappings = [{
      containerPort = 3000
      protocol      = "tcp"
    }]

    environment = [
      # SECURITY: Disable public signup
      { name = "GF_AUTH_DISABLE_SIGNOUT_MENU",       value = "false" },
      { name = "GF_USERS_ALLOW_SIGN_UP",             value = "false" },
      { name = "GF_AUTH_ANONYMOUS_ENABLED",          value = "false" },
      { name = "GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION", value = "false" },
      { name = "GF_SERVER_ROOT_URL",                 value = "https://${var.grafana_domain}" },
      { name = "GF_INSTALL_PLUGINS",                 value = "grafana-cloudwatch-datasource" },
      # SECURITY: Force HTTPS only
      { name = "GF_SERVER_PROTOCOL",                 value = "http" },  # TLS handled by ALB
      { name = "GF_SECURITY_COOKIE_SECURE",          value = "true" },
      { name = "GF_SECURITY_STRICT_TRANSPORT_SECURITY", value = "true" },
    ]

    secrets = [
      # Admin password from Secrets Manager — never hardcoded
      {
        name      = "GF_SECURITY_ADMIN_PASSWORD"
        valueFrom = var.grafana_admin_secret_arn
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.grafana.name
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = "grafana"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:3000/api/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  tags = merge(var.tags, {
    Name    = "${var.project_name}-grafana"
    Purpose = "SecurityDashboard"
  })
}

resource "aws_ecs_service" "grafana" {
  name            = "${var.project_name}-grafana"
  cluster         = aws_ecs_cluster.monitoring.id
  task_definition = aws_ecs_task_definition.grafana.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids    # Private — never public
    security_groups  = [aws_security_group.grafana.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.grafana.arn
    container_name   = "grafana"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.grafana_https]

  tags = merge(var.tags, {
    Name = "${var.project_name}-grafana-service"
  })
}

resource "aws_cloudwatch_log_group" "grafana" {
  name              = "/ecs/${var.project_name}/grafana"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

# ── Grafana Security Group ──────────────────────────────
resource "aws_security_group" "grafana" {
  name        = "${var.project_name}-grafana-sg"
  description = "Grafana: inbound from ALB only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Grafana port from ALB only"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [var.alb_sg_id]
  }

  egress {
    description = "HTTPS to AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-grafana-sg"
  })
}

# ── ALB for Grafana ─────────────────────────────────────
resource "aws_lb" "grafana" {
  name               = "${var.project_name}-grafana-alb"
  internal           = true    # SECURITY: Internal only — no public access
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.private_subnet_ids

  # SECURITY: Drop invalid HTTP headers
  drop_invalid_header_fields = true

  access_logs {
    bucket  = var.logging_bucket_name
    prefix  = "alb-logs/grafana"
    enabled = true
  }

  tags = merge(var.tags, {
    Name    = "${var.project_name}-grafana-alb"
    Purpose = "GrafanaAccess"
  })
}

resource "aws_lb_target_group" "grafana" {
  name        = "${var.project_name}-grafana-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/api/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }

  tags = var.tags
}

resource "aws_lb_listener" "grafana_https" {
  load_balancer_arn = aws_lb.grafana.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"    # TLS 1.3 preferred
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grafana.arn
  }

  tags = var.tags
}

# ── IAM Roles for Grafana ───────────────────────────────
resource "aws_iam_role" "grafana_task" {
  name = "${var.project_name}-grafana-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "grafana_cloudwatch" {
  name = "${var.project_name}-grafana-cloudwatch-policy"
  role = aws_iam_role.grafana_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # Read-only CloudWatch access for datasource
      Sid    = "CloudWatchReadOnly"
      Effect = "Allow"
      Action = [
        "cloudwatch:DescribeAlarmsForMetric",
        "cloudwatch:DescribeAlarmHistory",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetInsightRuleReport"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "grafana_execution" {
  name = "${var.project_name}-grafana-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "grafana_execution" {
  role       = aws_iam_role.grafana_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "grafana_secrets" {
  name = "${var.project_name}-grafana-secrets-policy"
  role = aws_iam_role.grafana_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetGrafanaSecret"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = var.grafana_admin_secret_arn
      },
      {
        Sid    = "KMSForSecret"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = var.kms_key_arn
      }
    ]
  })
}
