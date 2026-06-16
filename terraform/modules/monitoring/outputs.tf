output "grafana_alb_dns" {
  description = "Internal ALB DNS for Grafana"
  value       = aws_lb.grafana.dns_name
}

output "metrics_publisher_lambda_arn" {
  value = aws_lambda_function.metrics_publisher.arn
}

output "grafana_log_group" {
  value = aws_cloudwatch_log_group.grafana.name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.monitoring.name
}
