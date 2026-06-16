"""
Remediation Engine — Lambda entry point.
Receives EventBridge events from CloudTrail,
classifies the violation, and dispatches to the
correct remediator. Every action is audited.

Event flow:
  CloudTrail API call
    → EventBridge rule matches
      → This Lambda
        → Correct remediator
          → Fix applied
            → Audit logged
              → Alert sent
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from remediators.s3_remediator          import S3Remediator
from remediators.sg_remediator          import SGRemediator
from remediators.cloudtrail_remediator  import CloudTrailRemediator
from remediators.iam_remediator         import IAMRemediator
from audit_logger                       import AuditLogger

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── AWS Clients ──────────────────────────────────────────
sns_client = boto3.client("sns")

# ── Environment ──────────────────────────────────────────
PROJECT_NAME  = os.environ["PROJECT_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
AUDIT_TABLE   = os.environ["AUDIT_TABLE"]
DRY_RUN       = os.environ.get("DRY_RUN", "false").lower() == "true"
ENVIRONMENT   = os.environ.get("ENVIRONMENT", "dev")


# ─────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────

@dataclass
class RemediationEvent:
    """Normalised remediation trigger event."""
    event_id:      str
    event_name:    str
    event_source:  str
    resource_type: str
    resource_id:   str
    region:        str
    account_id:    str
    actor:         str         # Who triggered the violation
    timestamp:     str
    raw_event:     dict = field(default=None, repr=False)


@dataclass
class RemediationResult:
    """Result of a remediation action."""
    event_id:         str
    resource_id:      str
    resource_type:    str
    action_taken:     str
    success:          bool
    dry_run:          bool
    details:          dict = field(default_factory=dict)
    error:            Optional[str] = None
    timestamp:        str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ─────────────────────────────────────────────────────────
# EVENT → REMEDIATOR ROUTING TABLE
# Maps CloudTrail event names to remediator classes
# ─────────────────────────────────────────────────────────

REMEDIATION_ROUTING = {

    # ── S3 violations ───────────────────────────────────
    "PutBucketAcl":              "s3",
    "PutBucketPolicy":           "s3",
    "DeleteBucketPolicy":        "s3",
    "PutBucketPublicAccessBlock": "s3",

    # ── Security Group violations ────────────────────────
    "AuthorizeSecurityGroupIngress": "sg",
    "AuthorizeSecurityGroupEgress":  "sg",
    "CreateSecurityGroup":           "sg",

    # ── CloudTrail violations ────────────────────────────
    "StopLogging":  "cloudtrail",
    "DeleteTrail":  "cloudtrail",
    "UpdateTrail":  "cloudtrail",

    # ── IAM violations ───────────────────────────────────
    "AttachUserPolicy":   "iam",
    "PutUserPolicy":      "iam",
    "CreateAccessKey":    "iam",
    "AttachRolePolicy":   "iam",
}


# ─────────────────────────────────────────────────────────
# LAMBDA HANDLER
# ─────────────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Entry point — triggered by EventBridge.
    One Lambda invocation per CloudTrail event.
    """
    logger.info(
        "Remediation engine triggered%s: %s",
        " [DRY RUN]" if DRY_RUN else "",
        json.dumps(event, default=str)
    )

    audit = AuditLogger(table_name=AUDIT_TABLE)

    try:
        # Normalise EventBridge/CloudTrail event
        rem_event = normalise_event(event)
        if not rem_event:
            logger.info("Event does not require remediation — skipping")
            return {"statusCode": 200, "message": "No remediation needed"}

        logger.info(
            "Remediating: %s on %s (%s) by %s",
            rem_event.event_name,
            rem_event.resource_id,
            rem_event.resource_type,
            rem_event.actor,
        )

        # Get appropriate remediator
        remediator = get_remediator(rem_event)
        if not remediator:
            logger.warning(
                "No remediator found for event: %s",
                rem_event.event_name
            )
            return {"statusCode": 200, "message": "No remediator available"}

        # Execute remediation
        result = remediator.remediate(rem_event, dry_run=DRY_RUN)

        # Audit the action
        audit.log(rem_event, result)

        # Notify
        notify_remediation(rem_event, result)

        logger.info(
            "Remediation %s: %s on %s",
            "succeeded" if result.success else "failed",
            result.action_taken,
            result.resource_id,
        )

        return {
            "statusCode": 200,
            "result": {
                "success":      result.success,
                "action_taken": result.action_taken,
                "resource_id":  result.resource_id,
                "dry_run":      result.dry_run,
            }
        }

    except Exception as e:
        logger.error("Remediation engine error: %s", str(e), exc_info=True)
        notify_failure(str(e), event)
        raise


# ─────────────────────────────────────────────────────────
# EVENT NORMALISATION
# ─────────────────────────────────────────────────────────

def normalise_event(event: dict) -> Optional[RemediationEvent]:
    """
    Extract CloudTrail detail from EventBridge wrapper.
    Returns None if event doesn't need remediation.
    """
    # EventBridge wraps CloudTrail events under "detail"
    detail = event.get("detail", event)

    event_name   = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")
    region       = detail.get("awsRegion", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    account_id   = detail.get("recipientAccountId", "")
    timestamp    = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    event_id     = detail.get("eventID", f"evt-{timestamp}")

    # Skip if not in routing table
    if event_name not in REMEDIATION_ROUTING:
        return None

    # Extract actor (who caused the violation)
    user_identity = detail.get("userIdentity", {})
    actor = (
        user_identity.get("arn") or
        user_identity.get("userName") or
        user_identity.get("type", "Unknown")
    )

    # Extract resource from request parameters
    request_params = detail.get("requestParameters", {}) or {}
    resource_id, resource_type = extract_resource(event_name, request_params, detail)

    return RemediationEvent(
        event_id      = event_id,
        event_name    = event_name,
        event_source  = event_source,
        resource_type = resource_type,
        resource_id   = resource_id,
        region        = region,
        account_id    = account_id,
        actor         = actor,
        timestamp     = timestamp,
        raw_event     = event,
    )


def extract_resource(
    event_name: str,
    params: dict,
    detail: dict
) -> tuple:
    """Extract resource ID and type from event parameters."""

    if event_name in ["PutBucketAcl", "PutBucketPolicy",
                      "DeleteBucketPolicy", "PutBucketPublicAccessBlock"]:
        return params.get("bucketName", "unknown"), "S3Bucket"

    if event_name in ["AuthorizeSecurityGroupIngress",
                      "AuthorizeSecurityGroupEgress",
                      "CreateSecurityGroup"]:
        return params.get("groupId", "unknown"), "SecurityGroup"

    if event_name in ["StopLogging", "DeleteTrail", "UpdateTrail"]:
        name = params.get("name", "unknown")
        return name, "CloudTrailTrail"

    if event_name in ["AttachUserPolicy", "PutUserPolicy", "CreateAccessKey"]:
        return params.get("userName", "unknown"), "IAMUser"

    if event_name in ["AttachRolePolicy"]:
        return params.get("roleName", "unknown"), "IAMRole"

    return "unknown", "Unknown"


def get_remediator(event: RemediationEvent):
    """Instantiate the correct remediator for this event."""
    remediator_key = REMEDIATION_ROUTING.get(event.event_name)

    remediators = {
        "s3":          S3Remediator(project_name=PROJECT_NAME),
        "sg":          SGRemediator(project_name=PROJECT_NAME),
        "cloudtrail":  CloudTrailRemediator(project_name=PROJECT_NAME),
        "iam":         IAMRemediator(project_name=PROJECT_NAME),
    }

    return remediators.get(remediator_key)


# ─────────────────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────────────────

def notify_remediation(event: RemediationEvent, result: RemediationResult):
    """Notify SNS of remediation action — feeds into Phase 5 alerting."""
    status = "✅ Applied" if result.success else "❌ Failed"
    mode   = " [DRY RUN]" if result.dry_run else ""

    message = {
        "remediation_action": result.action_taken,
        "description": (
            f"Auto-remediation {status}{mode}\n"
            f"Event:    {event.event_name}\n"
            f"Resource: {result.resource_id}\n"
            f"Actor:    {event.actor}\n"
            f"Region:   {event.region}"
        ),
        "resource_id":     result.resource_id,
        "resource_type":   result.resource_type,
        "region":          event.region,
        "success":         result.success,
        "dry_run":         result.dry_run,
        "details":         result.details,
        "timestamp":       result.timestamp,
    }

    sns_client.publish(
        TopicArn = SNS_TOPIC_ARN,
        Subject  = f"🔧 Auto-Remediation{mode}: {result.action_taken} — {result.resource_id}",
        Message  = json.dumps(message, default=str),
    )


def notify_failure(error: str, event: dict):
    """Notify if the remediation engine itself fails."""
    sns_client.publish(
        TopicArn = SNS_TOPIC_ARN,
        Subject  = f"❌ Remediation Engine Failed — {PROJECT_NAME}",
        Message  = f"Remediation engine error:\n\n{error}\n\nEvent:\n{json.dumps(event, default=str, indent=2)}",
    )
