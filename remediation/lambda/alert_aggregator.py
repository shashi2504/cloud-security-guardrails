"""
Alert Aggregator
Prevents alert fatigue via deduplication and rate limiting.
Uses DynamoDB with TTL for state tracking.

Rules:
  CRITICAL → dedupe window: 1 hour
  HIGH     → dedupe window: 4 hours
  MEDIUM   → dedupe window: 24 hours (batch into digest)
"""

import boto3
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alert_router import SecurityAlert

logger = logging.getLogger(__name__)


DEDUP_WINDOWS = {
    "CRITICAL": 3600,       # 1 hour
    "HIGH":     14400,      # 4 hours
    "MEDIUM":   86400,      # 24 hours
    "LOW":      86400,
    "INFO":     3600,
}


class AlertAggregator:

    def __init__(self, table_name: str):
        self.table_name = table_name
        self._dynamodb  = boto3.resource("dynamodb")
        self.table      = self._dynamodb.Table(table_name)

    def is_duplicate(self, alert: "SecurityAlert") -> bool:
        """
        Check if identical alert was sent within dedup window.
        Returns True if alert should be suppressed.
        """
        alert_hash = self._compute_hash(alert)

        try:
            response = self.table.get_item(
                Key={"alert_hash": alert_hash}
            )
            item = response.get("Item")

            if item:
                logger.info(
                    "Duplicate suppressed — hash: %s | first seen: %s",
                    alert_hash[:8],
                    item.get("first_seen", "unknown")
                )
                return True

            return False

        except Exception as e:
            # On DynamoDB error — allow alert through (fail open)
            logger.error("Dedup check failed: %s — allowing alert", str(e))
            return False

    def record(self, alert: "SecurityAlert"):
        """
        Record that an alert was sent.
        TTL ensures auto-expiry after dedup window.
        """
        alert_hash   = self._compute_hash(alert)
        window       = DEDUP_WINDOWS.get(alert.severity, 3600)
        now          = int(datetime.now(timezone.utc).timestamp())
        expiry       = now + window

        self.table.put_item(Item={
            "alert_hash":  alert_hash,
            "alert_id":    alert.alert_id,
            "severity":    alert.severity,
            "alert_type":  alert.alert_type,
            "resource_id": alert.resource_id,
            "first_seen":  datetime.now(timezone.utc).isoformat(),
            "ttl":         expiry,    # DynamoDB auto-deletes after window
        })

        logger.info(
            "Alert recorded — hash: %s | expires in %ds",
            alert_hash[:8], window
        )

    def _compute_hash(self, alert: "SecurityAlert") -> str:
        """
        Compute stable hash for dedup.
        Same alert = same hash regardless of timestamp.
        """
        # Hash on: type + severity + resource + check
        # NOT on timestamp — same alert at different times = duplicate
        key = (
            f"{alert.alert_type}:"
            f"{alert.severity}:"
            f"{alert.resource_id}:"
            f"{alert.check_id or alert.title}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:32]
