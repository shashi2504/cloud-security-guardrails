"""
Findings Processor — Query and analyse CSPM findings.
Run locally to generate reports from DynamoDB data.

Usage:
  python findings_processor.py --scan-id scan-2024-01-15T02-00-00Z
  python findings_processor.py --latest
  python findings_processor.py --trend --days 30
"""

import argparse
import boto3
import json
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from boto3.dynamodb.conditions import Key, Attr


# ── AWS Resources ────────────────────────────────────────
dynamodb     = boto3.resource("dynamodb")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "cloud-sec-guardrails")
FINDINGS_TABLE = f"{PROJECT_NAME}-cspm-findings"
SCORE_TABLE    = f"{PROJECT_NAME}-cspm-scores"


def get_latest_scan_id() -> str:
    """Fetch the most recent scan ID from scores table."""
    table    = dynamodb.Table(SCORE_TABLE)
    response = table.scan(
        ProjectionExpression="scan_id, #ts",
        ExpressionAttributeNames={"#ts": "timestamp"},
    )
    items = sorted(
        response["Items"],
        key=lambda x: x["timestamp"],
        reverse=True
    )
    if not items:
        raise ValueError("No scans found in DynamoDB")
    return items[0]["scan_id"]


def get_findings_by_scan(scan_id: str) -> list:
    """Retrieve all findings for a specific scan."""
    table    = dynamodb.Table(FINDINGS_TABLE)
    response = table.query(
        KeyConditionExpression=Key("scan_id").eq(scan_id)
    )
    return response["Items"]


def get_critical_findings(scan_id: str) -> list:
    """Get only critical severity findings."""
    table    = dynamodb.Table(FINDINGS_TABLE)
    response = table.query(
        KeyConditionExpression=Key("scan_id").eq(scan_id),
        FilterExpression=Attr("severity").eq("critical")
    )
    return response["Items"]


def get_score_trend(days: int = 30) -> list:
    """
    Retrieve security score history for trend analysis.
    Returns list sorted by timestamp ascending.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H-%M-%SZ")

    table    = dynamodb.Table(SCORE_TABLE)
    response = table.scan(
        FilterExpression=Attr("timestamp").gte(cutoff_str)
    )

    return sorted(response["Items"], key=lambda x: x["timestamp"])


def generate_report(scan_id: str = None) -> dict:
    """
    Generate full security report for a scan.
    Defaults to latest scan if scan_id not provided.
    """
    if not scan_id:
        scan_id = get_latest_scan_id()

    findings = get_findings_by_scan(scan_id)

    # Group by severity
    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    # Group by framework
    by_framework = defaultdict(list)
    for f in findings:
        by_framework[f["framework"]].append(f)

    # Group by resource type
    by_resource = defaultdict(list)
    for f in findings:
        by_resource[f["resource_type"]].append(f)

    # Top failing checks
    check_counts = defaultdict(int)
    for f in findings:
        check_counts[f["check_title"]] += 1

    top_failing = sorted(
        check_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    report = {
        "scan_id":       scan_id,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "total_failed":  len(findings),
        "by_severity": {
            "critical": len(by_severity["critical"]),
            "high":     len(by_severity["high"]),
            "medium":   len(by_severity["medium"]),
        },
        "by_framework":   {k: len(v) for k, v in by_framework.items()},
        "by_resource":    {k: len(v) for k, v in by_resource.items()},
        "top_10_failing": [
            {"check": c, "count": n} for c, n in top_failing
        ],
        "critical_findings": [
            {
                "check_id":    f["check_id"],
                "title":       f["check_title"],
                "resource":    f["resource_id"],
                "region":      f["region"],
                "remediation": f["remediation"],
            }
            for f in by_severity["critical"]
        ]
    }

    return report


def print_dashboard(scan_id: str = None):
    """Print security dashboard to terminal."""
    report = generate_report(scan_id)

    print("\n" + "═" * 60)
    print("  CLOUD SECURITY POSTURE — CSPM REPORT")
    print("═" * 60)
    print(f"  Scan ID:     {report['scan_id']}")
    print(f"  Generated:   {report['generated_at']}")
    print("─" * 60)
    print("  SEVERITY BREAKDOWN")
    print(f"  🔴 Critical:  {report['by_severity']['critical']}")
    print(f"  🟠 High:      {report['by_severity']['high']}")
    print(f"  🟡 Medium:    {report['by_severity']['medium']}")
    print(f"  📊 Total Failed: {report['total_failed']}")
    print("─" * 60)
    print("  TOP 10 FAILING CHECKS")
    for i, item in enumerate(report["top_10_failing"], 1):
        print(f"  {i:2}. [{item['count']}x] {item['check'][:50]}")
    print("─" * 60)
    print("  CRITICAL FINDINGS — ACTION REQUIRED")
    for f in report["critical_findings"][:5]:
        print(f"\n  ▸ {f['check_id']}: {f['title']}")
        print(f"    Resource:    {f['resource']}")
        print(f"    Remediation: {f['remediation'][:80]}")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSPM Findings Processor")
    parser.add_argument("--scan-id",  help="Specific scan ID to query")
    parser.add_argument("--latest",   action="store_true", help="Show latest scan")
    parser.add_argument("--trend",    action="store_true", help="Show score trend")
    parser.add_argument("--days",     type=int, default=30, help="Days for trend")
    parser.add_argument("--json",     action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.trend:
        trend = get_score_trend(args.days)
        print(json.dumps(trend, indent=2, default=str))
    elif args.json:
        report = generate_report(args.scan_id)
        print(json.dumps(report, indent=2, default=str))
    else:
        print_dashboard(args.scan_id)
