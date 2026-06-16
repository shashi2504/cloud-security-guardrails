"""
Alert Router
Central routing engine for all security alerts.
Receives events from SNS/EventBridge, classifies them,
and dispatches to the correct notification channels.

Event sources:
  - CloudTrail CloudWatch alarms  (real-time violations)
  - Prowler CSPM scan completion  (daily findings)
  - Auto-remediation actions      (Phase 6)
  - Manual triggers               (testing)
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from slack_notifier  import SlackNotifier
from email_notifier  import EmailNotifier
from alert_aggregator import AlertAggregator

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── AWS Clients ──────────────────────────────────────────
sns_client = boto3.client("sns")

# ── Environment ──────────────────────────────────────────
PROJECT_NAME        = os.environ["PROJECT_NAME"]
SLACK_SECRET_ARN    = os.environ["SLACK_SECRET_ARN"]
ALERT_EMAIL_FROM    = os.environ["ALERT_EMAIL_FROM"]
EMAIL_CRITICAL_TO   = os.environ["EMAIL_CRITICAL_TO"]
EMAIL_TEAM_TO       = os.environ["EMAIL_TEAM_TO"]
AGGREGATOR_TABLE    = os.environ["AGGREGATOR_TABLE"]
ENVIRONMENT         = os.environ.get("ENVIRONMENT", "dev")


# ─────────────────────────────────────────────────────────
# ENUMS & DATA CLASSES
# ─────────────────────────────────────────────────────────

class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class AlertType(str, Enum):
    CLOUDTRAIL_ALARM    = "CLOUDTRAIL_ALARM"      # Real-time CloudWatch alarm
    CSPM_FINDING        = "CSPM_FINDING"           # Prowler finding
    CSPM_SCAN_COMPLETE  = "CSPM_SCAN_COMPLETE"     # Daily scan summary
    REMEDIATION_ACTION  = "REMEDIATION_ACTION"     # Auto-fix applied (Phase 6)
    MANUAL              = "MANUAL"                 # Test/manual trigger


@dataclass
class SecurityAlert:
    """Normalised alert structure — all sources map to this."""
    alert_id:    str
    alert_type:  AlertType
    severity:    AlertSeverity
    title:       str
    description: str
    resource_id: str
    region:      str
    timestamp:   str
    source:      str

    # Optional enrichment
    check_id:      Optional[str] = None
    remediation:   Optional[str] = None
    account_id:    Optional[str] = None
    scan_id:       Optional[str] = None
    score:         Optional[float] = None
    raw_event:     Optional[dict] = field(default=None, repr=False)


@dataclass
class RoutingDecision:
    """Which channels receive this alert and how."""
    alert:          SecurityAlert
    send_slack:     bool = False
    slack_channel:  str  = "#security-alerts"
    send_email:     bool = False
    email_to:       str  = ""
    immediate:      bool = True     # False = batch for digest
    should_page:    bool = False    # PagerDuty for critical


# ─────────────────────────────────────────────────────────
# LAMBDA HANDLER
# ─────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Entry point — receives SNS or EventBridge events.
    Normalises → routes → dispatches.
    """
    logger.info("Alert router triggered: %s", json.dumps(event, default=str))

    # Initialise notifiers
    slack      = SlackNotifier(secret_arn=SLACK_SECRET_ARN)
    email      = EmailNotifier(from_address=ALERT_EMAIL_FROM)
    aggregator = AlertAggregator(table_name=AGGREGATOR_TABLE)

    results = []

    # Handle SNS wrapper (CloudWatch alarms come via SNS)
    records = event.get("Records", [event])

    for record in records:
        try:
            # Extract actual message from SNS envelope if present
            if record.get("EventSource") == "aws:sns":
                message_str = record["Sns"]["Message"]
                try:
                    message = json.loads(message_str)
                except json.JSONDecodeError:
                    message = {"raw": message_str}
            else:
                message = record

            # Normalise to SecurityAlert
            alert = normalise_event(message)
            if not alert:
                logger.warning("Could not normalise event: %s", message)
                continue

            # Dedup check — skip if same alert sent recently
            if aggregator.is_duplicate(alert):
                logger.info("Duplicate alert suppressed: %s", alert.alert_id)
                continue

            # Route and dispatch
            decision = route_alert(alert)
            result   = dispatch_alert(alert, decision, slack, email)
            results.append(result)

            # Record sent alert for dedup
            aggregator.record(alert)

        except Exception as e:
            logger.error("Failed to process record: %s", str(e), exc_info=True)
            results.append({"status": "error", "error": str(e)})

    logger.info("Alert routing complete — %d alerts processed", len(results))
    return {"statusCode": 200, "results": results}


# ─────────────────────────────────────────────────────────
# EVENT NORMALISATION
# Map any source event to SecurityAlert
# ─────────────────────────────────────────────────────────

def normalise_event(event: dict) -> Optional[SecurityAlert]:
    """
    Detect event source and normalise to SecurityAlert.
    Returns None if event cannot be mapped.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── CloudWatch Alarm (CloudTrail violations) ────────
    if event.get("AlarmName") or event.get("detail-type") == "CloudWatch Alarm State Change":
        return _normalise_cloudwatch_alarm(event, timestamp)

    # ── CSPM Scan Complete ──────────────────────────────
    if event.get("source") == "scheduled" or event.get("scan_id"):
        return _normalise_cspm_scan(event, timestamp)

    # ── CSPM Finding (individual) ───────────────────────
    if event.get("check_id") or event.get("finding_id"):
        return _normalise_cspm_finding(event, timestamp)

    # ── Remediation Action ──────────────────────────────
    if event.get("remediation_action"):
        return _normalise_remediation(event, timestamp)

    # ── Raw SNS message ─────────────────────────────────
    if event.get("raw"):
        return SecurityAlert(
            alert_id    = f"raw-{timestamp}",
            alert_type  = AlertType.MANUAL,
            severity    = AlertSeverity.INFO,
            title       = "Security Notification",
            description = event["raw"],
            resource_id = "N/A",
            region      = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            timestamp   = timestamp,
            source      = "manual",
            raw_event   = event,
        )

    return None


def _normalise_cloudwatch_alarm(event: dict, timestamp: str) -> SecurityAlert:
    """Map CloudWatch alarm state change to SecurityAlert."""
    alarm_name   = event.get("AlarmName", event.get("detail", {}).get("alarmName", "Unknown"))
    alarm_desc   = event.get("AlarmDescription", "")
    new_state    = event.get("NewStateValue", event.get("detail", {}).get("state", {}).get("value", "ALARM"))
    reason       = event.get("NewStateReason", "")

    # Infer severity from alarm name
    severity = AlertSeverity.HIGH
    if any(k in alarm_name.lower() for k in ["root", "cloudtrail", "mfa"]):
        severity = AlertSeverity.CRITICAL
    elif any(k in alarm_name.lower() for k in ["unauthorized", "sg-change", "iam"]):
        severity = AlertSeverity.HIGH

    return SecurityAlert(
        alert_id    = f"cw-{alarm_name}-{timestamp}",
        alert_type  = AlertType.CLOUDTRAIL_ALARM,
        severity    = severity,
        title       = f"CloudWatch Alarm: {alarm_name}",
        description = alarm_desc or reason,
        resource_id = alarm_name,
        region      = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        timestamp   = timestamp,
        source      = "cloudwatch-alarm",
        raw_event   = event,
    )


def _normalise_cspm_scan(event: dict, timestamp: str) -> SecurityAlert:
    """Map CSPM scan completion event to SecurityAlert."""
    score    = float(event.get("score",    0))
    critical = int(event.get("critical",   0))
    high     = int(event.get("high",       0))
    scan_id  = event.get("scan_id",       "unknown")

    # Severity based on score and critical finding count
    if critical > 0 or score < 60:
        severity = AlertSeverity.CRITICAL
    elif score < 75 or high > 5:
        severity = AlertSeverity.HIGH
    else:
        severity = AlertSeverity.INFO

    return SecurityAlert(
        alert_id    = f"cspm-scan-{scan_id}",
        alert_type  = AlertType.CSPM_SCAN_COMPLETE,
        severity    = severity,
        title       = f"CSPM Scan Complete — Score: {score:.0f}/100",
        description = (
            f"Daily security scan completed.\n"
            f"Score: {score:.0f}/100 | "
            f"Critical: {critical} | "
            f"High: {high} | "
            f"Total failed: {event.get('failed', 0)}"
        ),
        resource_id = "AWS Account",
        region      = os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        timestamp   = timestamp,
        source      = "prowler-cspm",
        scan_id     = scan_id,
        score       = score,
        raw_event   = event,
    )


def _normalise_cspm_finding(event: dict, timestamp: str) -> SecurityAlert:
    """Map individual CSPM finding to SecurityAlert."""
    severity_map = {
        "critical": AlertSeverity.CRITICAL,
        "high":     AlertSeverity.HIGH,
        "medium":   AlertSeverity.MEDIUM,
        "low":      AlertSeverity.LOW,
    }

    raw_sev  = event.get("severity", "medium").lower()
    severity = severity_map.get(raw_sev, AlertSeverity.MEDIUM)

    return SecurityAlert(
        alert_id    = event.get("finding_id", f"finding-{timestamp}"),
        alert_type  = AlertType.CSPM_FINDING,
        severity    = severity,
        title       = event.get("check_title", "Security Finding"),
        description = event.get("description", ""),
        resource_id = event.get("resource_id",  "Unknown"),
        region      = event.get("region",       "us-east-1"),
        timestamp   = timestamp,
        source      = "prowler",
        check_id    = event.get("check_id"),
        remediation = event.get("remediation"),
        scan_id     = event.get("scan_id"),
        raw_event   = event,
    )


def _normalise_remediation(event: dict, timestamp: str) -> SecurityAlert:
    """Map auto-remediation action to SecurityAlert."""
    return SecurityAlert(
        alert_id    = f"remediation-{timestamp}",
        alert_type  = AlertType.REMEDIATION_ACTION,
        severity    = AlertSeverity.INFO,
        title       = f"Auto-Remediation Applied: {event.get('remediation_action')}",
        description = event.get("description", "Automatic remediation was applied."),
        resource_id = event.get("resource_id", "Unknown"),
        region      = event.get("region",      "us-east-1"),
        timestamp   = timestamp,
        source      = "auto-remediation",
        raw_event   = event,
    )


# ─────────────────────────────────────────────────────────
# ROUTING LOGIC
# Decides which channels get which alerts
# ─────────────────────────────────────────────────────────

def route_alert(alert: SecurityAlert) -> RoutingDecision:
    """
    Apply routing rules based on severity and type.
    Returns RoutingDecision with channel config.
    """
    decision = RoutingDecision(alert=alert)

    if alert.severity == AlertSeverity.CRITICAL:
        # Critical → every channel, immediately, page on-call
        decision.send_slack    = True
        decision.slack_channel = "#security-critical"
        decision.send_email    = True
        decision.email_to      = EMAIL_CRITICAL_TO
        decision.immediate     = True
        decision.should_page   = True

    elif alert.severity == AlertSeverity.HIGH:
        # High → Slack + email, immediate
        decision.send_slack    = True
        decision.slack_channel = "#security-alerts"
        decision.send_email    = True
        decision.email_to      = EMAIL_TEAM_TO
        decision.immediate     = True
        decision.should_page   = False

    elif alert.severity == AlertSeverity.MEDIUM:
        # Medium → Slack only, batched digest
        decision.send_slack    = True
        decision.slack_channel = "#security-alerts"
        decision.send_email    = False
        decision.immediate     = False    # Goes into hourly digest

    elif alert.alert_type == AlertType.CSPM_SCAN_COMPLETE:
        # Scan summary → dedicated channel regardless of severity
        decision.send_slack    = True
        decision.slack_channel = "#security-reports"
        decision.send_email    = True
        decision.email_to      = EMAIL_TEAM_TO
        decision.immediate     = True

    elif alert.alert_type == AlertType.REMEDIATION_ACTION:
        # Remediation confirmations → reports channel
        decision.send_slack    = True
        decision.slack_channel = "#security-reports"
        decision.send_email    = False
        decision.immediate     = True

    logger.info(
        "Routing decision — Severity: %s | Slack: %s (%s) | Email: %s | Page: %s",
        alert.severity,
        decision.slack_channel if decision.send_slack else "none",
        "immediate" if decision.immediate else "batched",
        decision.email_to if decision.send_email else "none",
        decision.should_page,
    )

    return decision


# ─────────────────────────────────────────────────────────
# DISPATCH
# ─────────────────────────────────────────────────────────

def dispatch_alert(
    alert:    SecurityAlert,
    decision: RoutingDecision,
    slack:    "SlackNotifier",
    email:    "EmailNotifier",
) -> dict:
    """Send alert to all routed channels."""
    results = {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "channels": []
    }

    if decision.send_slack:
        try:
            slack.send(
                alert   = alert,
                channel = decision.slack_channel,
                urgent  = decision.immediate,
            )
            results["channels"].append("slack")
            logger.info("Slack alert sent to %s", decision.slack_channel)
        except Exception as e:
            logger.error("Slack delivery failed: %s", str(e))

    if decision.send_email:
        try:
            email.send(
                alert   = alert,
                to      = decision.email_to,
                urgent  = decision.immediate,
            )
            results["channels"].append("email")
            logger.info("Email alert sent to %s", decision.email_to)
        except Exception as e:
            logger.error("Email delivery failed: %s", str(e))

    return results
