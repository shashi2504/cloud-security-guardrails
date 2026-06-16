"""
Audit Logger
Immutable audit trail of every remediation action.
Every fix is logged to DynamoDB with full context —
who caused the violation, what was fixed, when, by what.
"""

import boto3
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_engine import RemediationEvent, RemediationResult

logger = logging.getLogger(__name__)


class AuditLogger:

    def __init__(self, table_name: str):
        self.table_name = table_name
        self.dynamodb   = boto3.resource("dynamodb")
        self.table      = self.dynamodb.Table(table_name)

    def log(
        self,
        event:  "RemediationEvent",
        result: "RemediationResult"
    ):
        """
        Write immutable audit record to DynamoDB.
        Records cannot be deleted — TTL set to 7 years.
        """
        now = datetime.now(timezone.utc)

        audit_record = {
            # ── Keys ────────────────────────────────────
            "event_id":   event.event_id,
            "timestamp":  now.isoformat(),

            # ── Violation ───────────────────────────────
            "event_name":    event.event_name,
            "event_source":  event.event_source,
            "resource_id":   event.resource_id,
            "resource_type": event.resource_type,
            "region":        event.region,
            "account_id":    event.account_id,

            # ── Who caused it ───────────────────────────
            "actor":         event.actor,
            "violation_time": event.timestamp,

            # ── What was done ───────────────────────────
            "action_taken":  result.action_taken,
            "success":       result.success,
            "dry_run":       result.dry_run,
            "details":       json.dumps(result.details, default=str),

            # ── Error if any ────────────────────────────
            "error":         result.error or "none",

            # ── Metadata ────────────────────────────────
            "remediation_time": now.isoformat(),
            "latency_seconds":  self._compute_latency(event.timestamp, now),

            # ── TTL — 7 years for compliance ────────────
            "ttl": int(now.timestamp()) + (7 * 365 * 86400),
        }

        self.table.put_item(Item=audit_record)

        logger.info(
            "Audit logged — event: %s | resource: %s | action: %s | success: %s",
            event.event_name,
            event.resource_id,
            result.action_taken,
            result.success,
        )

    def _compute_latency(self, violation_time: str, remediation_time: datetime) -> str:
        """
        Compute seconds between violation and remediation.
        Key metric — shows how fast auto-remediation responds.
        """
        try:
            # Parse ISO format violation time
            vt = datetime.fromisoformat(
                violation_time.replace("Z", "+00:00")
            )
            delta = (remediation_time - vt).total_seconds()
            return str(round(delta, 1))
        except Exception:
            return "unknown"
