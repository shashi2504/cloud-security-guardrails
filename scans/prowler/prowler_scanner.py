"""
Prowler CSPM Scanner — Lambda entry point
Runs Prowler against the AWS account on a schedule,
stores results in S3, and pushes findings to DynamoDB.
"""

import boto3
import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# ── Logging ────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS Clients ─────────────────────────────────────────
s3_client        = boto3.client("s3")
dynamodb         = boto3.resource("dynamodb")
sns_client       = boto3.client("sns")
securityhub      = boto3.client("securityhub")

# ── Environment Variables ───────────────────────────────
RESULTS_BUCKET   = os.environ["RESULTS_BUCKET"]
FINDINGS_TABLE   = os.environ["FINDINGS_TABLE"]
SNS_TOPIC_ARN    = os.environ["SNS_TOPIC_ARN"]
AWS_REGION       = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
PROJECT_NAME     = os.environ["PROJECT_NAME"]
SCORE_TABLE      = os.environ["SCORE_TABLE"]


def lambda_handler(event, context):
    """
    Main Lambda handler.
    Triggered by EventBridge on schedule or manually.
    """
    logger.info("Starting CSPM scan — %s", datetime.now(timezone.utc).isoformat())

    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    scan_id        = f"scan-{scan_timestamp}"

    try:
        # Step 1 — Run Prowler scans
        findings = run_prowler_scans(scan_id, scan_timestamp)

        # Step 2 — Process and categorise findings
        processed = process_findings(findings, scan_id, scan_timestamp)

        # Step 3 — Calculate security score
        score = calculate_security_score(processed)

        # Step 4 — Store results
        store_findings_dynamodb(processed, scan_id)
        store_score_dynamodb(score, scan_id, scan_timestamp)
        upload_reports_s3(scan_id, scan_timestamp)

        # Step 5 — Alert on critical findings
        alert_critical_findings(processed, score, scan_id)

        # Step 6 — Summary log
        summary = build_summary(processed, score, scan_id)
        logger.info("Scan complete: %s", json.dumps(summary))

        return {
            "statusCode": 200,
            "scanId": scan_id,
            "summary": summary
        }

    except Exception as e:
        logger.error("CSPM scan failed: %s", str(e), exc_info=True)
        notify_scan_failure(str(e), scan_id)
        raise


# ─────────────────────────────────────────────────────────
# PROWLER EXECUTION
# ─────────────────────────────────────────────────────────

def run_prowler_scans(scan_id: str, timestamp: str) -> list:
    """
    Run multiple Prowler compliance frameworks.
    Returns combined list of all findings.
    """
    all_findings = []

    # Compliance frameworks to run
    frameworks = [
        {
            "name": "cis_aws_foundations_benchmark_v1_5",
            "label": "CIS AWS Foundations v1.5"
        },
        {
            "name": "aws_foundational_security_best_practices",
            "label": "AWS Foundational Security Best Practices"
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        for framework in frameworks:
            logger.info("Running framework: %s", framework["label"])

            output_prefix = f"{tmpdir}/{framework['name']}"

            cmd = [
                sys.executable, "-m", "prowler",
                "aws",
                "--compliance", framework["name"],
                "--region", AWS_REGION,
                "--output-formats", "json-ocsf",
                "--output-directory", tmpdir,
                "--output-filename", framework["name"],
                "--severity", "critical", "high", "medium",
                "--ignore-exit-code-3",    # Medium findings don't fail
                "--no-banner",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600    # 10 min timeout per framework
            )

            if result.returncode not in [0, 3]:
                logger.error(
                    "Prowler failed for %s: %s",
                    framework["name"],
                    result.stderr
                )
                continue

            # Parse OCSF JSON output
            json_path = Path(f"{output_prefix}.ocsf.json")
            if json_path.exists():
                with open(json_path) as f:
                    framework_findings = json.load(f)
                    for finding in framework_findings:
                        finding["framework"] = framework["name"]
                        finding["framework_label"] = framework["label"]
                    all_findings.extend(framework_findings)
                logger.info(
                    "Framework %s: %d findings",
                    framework["name"],
                    len(framework_findings)
                )
            else:
                logger.warning("No output file for %s", framework["name"])

    logger.info("Total raw findings: %d", len(all_findings))
    return all_findings


# ─────────────────────────────────────────────────────────
# FINDINGS PROCESSING
# ─────────────────────────────────────────────────────────

def process_findings(raw_findings: list, scan_id: str, timestamp: str) -> dict:
    """
    Categorise findings by severity and status.
    Returns structured findings dict.
    """
    processed = {
        "scan_id":   scan_id,
        "timestamp": timestamp,
        "critical":  [],
        "high":      [],
        "medium":    [],
        "passed":    [],
        "failed":    [],
        "total":     len(raw_findings),
    }

    severity_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "medium",   # Promote low to medium for visibility
        "info":     "medium",
    }

    for finding in raw_findings:

        # ── Normalise status ───────────────────────────
        status = finding.get("status", "").lower()
        is_failed = status in ["failed", "fail", "error"]

        # ── Normalise severity ─────────────────────────
        raw_severity = finding.get("severity", "medium").lower()
        severity     = severity_map.get(raw_severity, "medium")

        # ── Build normalised finding ───────────────────
        normalised = {
            "scan_id":        scan_id,
            "finding_id":     finding.get("finding_uid", ""),
            "check_id":       finding.get("check_id", ""),
            "check_title":    finding.get("check_title", ""),
            "severity":       severity,
            "status":         "FAILED" if is_failed else "PASSED",
            "resource_id":    finding.get("resource_uid", ""),
            "resource_type":  finding.get("resource_type", ""),
            "region":         finding.get("cloud", {}).get("region", AWS_REGION),
            "framework":      finding.get("framework", ""),
            "description":    finding.get("description", ""),
            "remediation":    finding.get("remediation", {}).get("recommendation", {}).get("text", ""),
            "timestamp":      timestamp,
        }

        # ── Route to correct bucket ────────────────────
        if is_failed:
            processed["failed"].append(normalised)
            if severity in ["critical", "high", "medium"]:
                processed[severity].append(normalised)
        else:
            processed["passed"].append(normalised)

    logger.info(
        "Findings processed — Critical: %d | High: %d | Medium: %d | Passed: %d",
        len(processed["critical"]),
        len(processed["high"]),
        len(processed["medium"]),
        len(processed["passed"]),
    )

    return processed


# ─────────────────────────────────────────────────────────
# SECURITY SCORE CALCULATION
# ─────────────────────────────────────────────────────────

def calculate_security_score(processed: dict) -> dict:
    """
    Calculate weighted security score.

    Weighting:
      Critical findings → -15 points each  (max -60)
      High findings     → -5 points each   (max -30)
      Medium findings   → -1 point each    (max -10)

    Score = max(0, 100 - deductions)
    """
    total    = processed["total"]
    passed   = len(processed["passed"])
    critical = len(processed["critical"])
    high     = len(processed["high"])
    medium   = len(processed["medium"])

    # Weighted deductions
    deductions = (
        min(critical * 15, 60) +   # Cap critical deduction at 60
        min(high * 5, 30)     +   # Cap high deduction at 30
        min(medium * 1, 10)        # Cap medium deduction at 10
    )

    score = max(0, 100 - deductions)

    # Compliance pass rate
    pass_rate = round((passed / total * 100), 1) if total > 0 else 0

    # Risk rating
    if score >= 90:
        rating = "EXCELLENT"
    elif score >= 75:
        rating = "GOOD"
    elif score >= 60:
        rating = "FAIR"
    elif score >= 40:
        rating = "POOR"
    else:
        rating = "CRITICAL"

    result = {
        "score":       score,
        "rating":      rating,
        "pass_rate":   pass_rate,
        "total":       total,
        "passed":      passed,
        "failed":      len(processed["failed"]),
        "critical":    critical,
        "high":        high,
        "medium":      medium,
        "deductions":  deductions,
    }

    logger.info("Security score: %d/100 (%s)", score, rating)
    return result


# ─────────────────────────────────────────────────────────
# STORAGE
# ─────────────────────────────────────────────────────────

def store_findings_dynamodb(processed: dict, scan_id: str):
    """
    Store individual findings in DynamoDB.
    Each failed finding gets its own item for querying.
    """
    table  = dynamodb.Table(FINDINGS_TABLE)
    failed = processed["failed"]

    if not failed:
        logger.info("No failed findings to store")
        return

    # Batch write — 25 items per batch (DynamoDB limit)
    with table.batch_writer() as batch:
        for finding in failed:
            batch.put_item(Item={
                # Partition key: scan_id
                # Sort key: finding_id
                "scan_id":       finding["scan_id"],
                "finding_id":    finding["finding_id"] or f"{finding['check_id']}-{finding['resource_id']}",
                "check_id":      finding["check_id"],
                "check_title":   finding["check_title"],
                "severity":      finding["severity"],
                "status":        finding["status"],
                "resource_id":   finding["resource_id"],
                "resource_type": finding["resource_type"],
                "region":        finding["region"],
                "framework":     finding["framework"],
                "description":   finding["description"],
                "remediation":   finding["remediation"],
                "timestamp":     finding["timestamp"],
                # TTL — auto-expire after 90 days
                "ttl": int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
            })
[O
    logger.info("Stored %d findings in DynamoDB", len(failed))


def store_score_dynamodb(score: dict, scan_id: str, timestamp: str):
    """
    Store security score for trend tracking.
    Allows graphing score over time in Grafana.
    """
    table = dynamodb.Table(SCORE_TABLE)

    table.put_item(Item={
        "scan_id":    scan_id,
        "timestamp":  timestamp,
        "score":      score["score"],
        "rating":     score["rating"],
        "pass_rate":  str(score["pass_rate"]),
        "total":      score["total"],
        "passed":     score["passed"],
        "failed":     score["failed"],
        "critical":   score["critical"],
        "high":       score["high"],
        "medium":     score["medium"],
        # TTL — keep 1 year of score history
        "ttl": int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
    })

    logger.info("Score stored: %d/100 (%s)", score["score"], score["rating"])


def upload_reports_s3(scan_id: str, timestamp: str):
    """
    Upload Prowler HTML and JSON reports to S3.
    Organised by date for easy retrieval.
    """
    date_prefix = timestamp[:10]    # YYYY-MM-DD

    report_dir = Path("/tmp")
    for report_file in report_dir.glob("*.json"):
        s3_key = f"prowler-reports/{date_prefix}/{scan_id}/{report_file.name}"
        s3_client.upload_file(
            str(report_file),
            RESULTS_BUCKET,
            s3_key,
            ExtraArgs={
                "ServerSideEncryption": "aws:kms",
                "ContentType": "application/json"
            }
        )
        logger.info("Uploaded: s3://%s/%s", RESULTS_BUCKET, s3_key)


# ─────────────────────────────────────────────────────────
# ALERTING
# ─────────────────────────────────────────────────────────

def alert_critical_findings(processed: dict, score: dict, scan_id: str):
    """
    Send SNS alert if critical findings exist
    or score drops below threshold.
    """
    critical_findings = processed["critical"]
    should_alert = (
        len(critical_findings) > 0 or
        score["score"] < 70
    )

    if not should_alert:
        logger.info("No alerts needed — score: %d, critical: %d",
                    score["score"], len(critical_findings))
        return

    # Build alert message
    critical_list = "\n".join([
        f"  • [{f['check_id']}] {f['check_title']} — {f['resource_id']}"
        for f in critical_findings[:10]    # First 10 to avoid message size limits
    ])

    more_msg = (
        f"\n  ... and {len(critical_findings) - 10} more"
        if len(critical_findings) > 10 else ""
    )

    message = f"""
🚨 CSPM SECURITY ALERT — {PROJECT_NAME.upper()}
{'─' * 50}

Scan ID:        {scan_id}
Security Score: {score['score']}/100 ({score['rating']})
Pass Rate:      {score['pass_rate']}%

FINDINGS SUMMARY:
  Critical: {score['critical']}
  High:     {score['high']}
  Medium:   {score['medium']}
  Passed:   {score['passed']}

CRITICAL FINDINGS:
{critical_list}{more_msg}

{'─' * 50}
Action Required: Review findings in DynamoDB table {FINDINGS_TABLE}
Reports: s3://{RESULTS_BUCKET}/prowler-reports/
"""

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"🚨 CSPM Alert — Score: {score['score']}/100 | Critical: {score['critical']}",
        Message=message
    )

    logger.info("Alert sent — critical: %d, score: %d",
                len(critical_findings), score["score"])


def notify_scan_failure(error: str, scan_id: str):
    """Notify if the scan itself fails."""
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"❌ CSPM Scan Failed — {scan_id}",
        Message=f"CSPM scan {scan_id} failed with error:\n\n{error}"
    )


def build_summary(processed: dict, score: dict, scan_id: str) -> dict:
    """Build summary dict for Lambda response."""
    return {
        "scan_id":  scan_id,
        "score":    score["score"],
        "rating":   score["rating"],
        "total":    processed["total"],
        "passed":   len(processed["passed"]),
        "failed":   len(processed["failed"]),
        "critical": len(processed["critical"]),
        "high":     len(processed["high"]),
        "medium":   len(processed["medium"]),
    }
