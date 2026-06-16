"""
CloudWatch Metrics Publisher
Reads CSPM scan results from DynamoDB and publishes
them as CloudWatch custom metrics for dashboards and alarms.

Runs as a Lambda after every Prowler scan completes.
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from boto3.dynamodb.conditions import Key, Attr
from collections import defaultdict

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS Clients ──────────────────────────────────────────
cloudwatch = boto3.client("cloudwatch")
dynamodb   = boto3.resource("dynamodb")

# ── Environment ──────────────────────────────────────────
PROJECT_NAME   = os.environ["PROJECT_NAME"]
FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
SCORE_TABLE    = os.environ["SCORE_TABLE"]
NAMESPACE      = f"{PROJECT_NAME}/SecurityMetrics"


def lambda_handler(event, context):
    """
    Entry point — triggered by EventBridge after Prowler scan.
    Reads latest scan results and publishes to CloudWatch.
    """
    logger.info("Publishing metrics to CloudWatch namespace: %s", NAMESPACE)

    try:
        # Fetch latest scan data
        score_data    = get_latest_score()
        findings_data = get_latest_findings(score_data["scan_id"])

        # Publish all metric groups
        publish_security_score_metrics(score_data)
        publish_findings_metrics(findings_data)
        publish_compliance_metrics(findings_data)
        publish_resource_metrics(findings_data)

        logger.info("All metrics published successfully")
        return {"statusCode": 200, "message": "Metrics published"}

    except Exception as e:
        logger.error("Metrics publish failed: %s", str(e), exc_info=True)
        raise


# ─────────────────────────────────────────────────────────
# DATA FETCHING
# ─────────────────────────────────────────────────────────

def get_latest_score() -> dict:
    """Fetch most recent security score from DynamoDB."""
    table    = dynamodb.Table(SCORE_TABLE)
    response = table.scan()

    items = sorted(
        response["Items"],
        key=lambda x: x["timestamp"],
        reverse=True
    )

    if not items:
        raise ValueError("No scan scores found in DynamoDB")

    latest = items[0]
    logger.info(
        "Latest scan: %s | Score: %s",
        latest["scan_id"],
        latest["score"]
    )
    return latest


def get_latest_findings(scan_id: str) -> list:
    """Fetch all findings for the most recent scan."""
    table    = dynamodb.Table(FINDINGS_TABLE)
    response = table.query(
        KeyConditionExpression=Key("scan_id").eq(scan_id)
    )
    return response["Items"]


# ─────────────────────────────────────────────────────────
# METRIC PUBLISHERS
# ─────────────────────────────────────────────────────────

def publish_security_score_metrics(score_data: dict):
    """
    Publish top-level security posture metrics.
    These power the headline dashboard panels.
    """
    now = datetime.now(timezone.utc)

    metrics = [
        # ── Core Score ─────────────────────────────────
        {
            "MetricName": "SecurityScore",
            "Value":      float(score_data["score"]),
            "Unit":       "None",
            "Dimensions": [
                {"Name": "Project",     "Value": PROJECT_NAME},
                {"Name": "Environment", "Value": "dev"},
            ],
            "Timestamp": now,
        },

        # ── Pass Rate ───────────────────────────────────
        {
            "MetricName": "PassRate",
            "Value":      float(score_data.get("pass_rate", 0)),
            "Unit":       "Percent",
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
            "Timestamp": now,
        },

        # ── Total Checks ────────────────────────────────
        {
            "MetricName": "TotalChecks",
            "Value":      float(score_data.get("total", 0)),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
            "Timestamp": now,
        },

        # ── Passed Checks ───────────────────────────────
        {
            "MetricName": "PassedChecks",
            "Value":      float(score_data.get("passed", 0)),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
            "Timestamp": now,
        },

        # ── Failed Checks ───────────────────────────────
        {
            "MetricName": "FailedChecks",
            "Value":      float(score_data.get("failed", 0)),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
            "Timestamp": now,
        },
    ]

    _batch_put_metrics(metrics)
    logger.info("Score metrics published — Score: %s", score_data["score"])


def publish_findings_metrics(findings: list):
    """
    Publish per-severity finding counts.
    Powers severity breakdown charts.
    """
    now = datetime.now(timezone.utc)

    # Count by severity
    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f.get("severity", "medium")] += 1

    metrics = []
    for severity in ["critical", "high", "medium"]:
        count = severity_counts.get(severity, 0)

        metrics.append({
            "MetricName": "FindingCount",
            "Value":      float(count),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project",  "Value": PROJECT_NAME},
                {"Name": "Severity", "Value": severity.capitalize()},
            ],
            "Timestamp": now,
        })

        # Individual named metrics for simple alarm targeting
        metrics.append({
            "MetricName": f"{severity.capitalize()}Findings",
            "Value":      float(count),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
            "Timestamp": now,
        })

    _batch_put_metrics(metrics)
    logger.info(
        "Findings metrics published — Crit: %d | High: %d | Med: %d",
        severity_counts["critical"],
        severity_counts["high"],
        severity_counts["medium"],
    )


def publish_compliance_metrics(findings: list):
    """
    Publish per-framework compliance metrics.
    Tracks CIS vs FSBP pass rates separately.
    """
    now = datetime.now(timezone.utc)

    # Group by framework
    framework_findings = defaultdict(list)
    for f in findings:
        framework = f.get("framework", "unknown")
        framework_findings[framework].append(f)

    metrics = []
    for framework, fw_findings in framework_findings.items():
        failed_count = len(fw_findings)

        # Shorten framework name for dimension value (25 char limit)
        fw_short = (
            "CIS"  if "cis"  in framework.lower() else
            "FSBP" if "foundational" in framework.lower() else
            framework[:25]
        )

        metrics.append({
            "MetricName": "ComplianceFailures",
            "Value":      float(failed_count),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project",   "Value": PROJECT_NAME},
                {"Name": "Framework", "Value": fw_short},
            ],
            "Timestamp": now,
        })

    _batch_put_metrics(metrics)
    logger.info("Compliance metrics published — %d frameworks", len(framework_findings))


def publish_resource_metrics(findings: list):
    """
    Publish per-resource-type finding counts.
    Shows which AWS services have the most issues.
    """
    now = datetime.now(timezone.utc)

    resource_counts = defaultdict(int)
    for f in findings:
        rtype = f.get("resource_type", "Unknown")
        # Shorten AWS resource type names
        rtype_short = rtype.replace("AWS::", "").replace("::", "-")[:30]
        resource_counts[rtype_short] += 1

    # Top 10 resource types only — CloudWatch dimension limit
    top_resources = sorted(
        resource_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    metrics = []
    for resource_type, count in top_resources:
        metrics.append({
            "MetricName": "ResourceTypeFindings",
            "Value":      float(count),
            "Unit":       "Count",
            "Dimensions": [
                {"Name": "Project",      "Value": PROJECT_NAME},
                {"Name": "ResourceType", "Value": resource_type},
            ],
            "Timestamp": now,
        })

    _batch_put_metrics(metrics)
    logger.info("Resource metrics published — %d resource types", len(top_resources))


# ─────────────────────────────────────────────────────────
# CLOUDWATCH ALARMS ON CUSTOM METRICS
# ─────────────────────────────────────────────────────────

def create_score_alarms(sns_topic_arn: str):
    """
    Create CloudWatch alarms on CSPM custom metrics.
    Called once during setup — not on every Lambda run.
    """

    alarms = [

        # Score drops below 75
        {
            "AlarmName":          f"{PROJECT_NAME}-security-score-low",
            "AlarmDescription":   "Security score dropped below 75 — review findings",
            "MetricName":         "SecurityScore",
            "Namespace":          NAMESPACE,
            "Statistic":          "Minimum",
            "Period":             86400,       # Daily
            "EvaluationPeriods":  1,
            "Threshold":          75,
            "ComparisonOperator": "LessThanThreshold",
            "TreatMissingData":   "notBreaching",
            "AlarmActions":       [sns_topic_arn],
            "Dimensions": [
                {"Name": "Project",     "Value": PROJECT_NAME},
                {"Name": "Environment", "Value": "dev"},
            ],
        },

        # Any critical finding appears
        {
            "AlarmName":          f"{PROJECT_NAME}-critical-findings-detected",
            "AlarmDescription":   "Critical security findings detected — immediate action required",
            "MetricName":         "CriticalFindings",
            "Namespace":          NAMESPACE,
            "Statistic":          "Maximum",
            "Period":             86400,
            "EvaluationPeriods":  1,
            "Threshold":          1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData":   "notBreaching",
            "AlarmActions":       [sns_topic_arn],
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
        },

        # High findings spike
        {
            "AlarmName":          f"{PROJECT_NAME}-high-findings-spike",
            "AlarmDescription":   "High severity findings exceeded threshold",
            "MetricName":         "HighFindings",
            "Namespace":          NAMESPACE,
            "Statistic":          "Maximum",
            "Period":             86400,
            "EvaluationPeriods":  1,
            "Threshold":          10,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData":   "notBreaching",
            "AlarmActions":       [sns_topic_arn],
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
        },

        # Pass rate drops below 80%
        {
            "AlarmName":          f"{PROJECT_NAME}-pass-rate-low",
            "AlarmDescription":   "Compliance pass rate below 80%",
            "MetricName":         "PassRate",
            "Namespace":          NAMESPACE,
            "Statistic":          "Minimum",
            "Period":             86400,
            "EvaluationPeriods":  1,
            "Threshold":          80,
            "ComparisonOperator": "LessThanThreshold",
            "TreatMissingData":   "notBreaching",
            "AlarmActions":       [sns_topic_arn],
            "Dimensions": [
                {"Name": "Project", "Value": PROJECT_NAME},
            ],
        },
    ]

    for alarm in alarms:
        cloudwatch.put_metric_alarm(**alarm)
        logger.info("Alarm created: %s", alarm["AlarmName"])


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _batch_put_metrics(metrics: list):
    """
    Put metrics in batches of 20 (CloudWatch API limit).
    Handles chunking automatically.
    """
    chunk_size = 20
    chunks = [
        metrics[i:i + chunk_size]
        for i in range(0, len(metrics), chunk_size)
    ]

    for chunk in chunks:
        cloudwatch.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=chunk
        )
