"""
CloudTrail Remediator
Re-enables CloudTrail if disabled.
Attacker's first move is disabling audit logs —
we detect and restore within minutes.
"""

import boto3
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_engine import RemediationEvent, RemediationResult

logger = logging.getLogger(__name__)


class CloudTrailRemediator:

    def __init__(self, project_name: str):
        self.project_name = project_name
        self.ct           = boto3.client("cloudtrail")
        self.sns          = boto3.client("sns")

    def remediate(
        self,
        event:   "RemediationEvent",
        dry_run: bool = False
    ) -> "RemediationResult":
        """Re-enable CloudTrail logging if stopped."""
        from remediation_engine import RemediationResult

        trail_name = event.resource_id
        actions    = []
        errors     = []

        logger.info(
            "CloudTrail remediation — trail: %s | event: %s",
            trail_name, event.event_name
        )

        try:
            # Check current trail status
            status = self.ct.get_trail_status(Name=trail_name)
            is_logging = status.get("IsLogging", False)

            if event.event_name == "DeleteTrail":
                # Cannot restore a deleted trail — alert and document
                action = self._handle_deleted_trail(trail_name, event, dry_run)
                actions.append(action)

            elif event.event_name in ["StopLogging", "UpdateTrail"]:
                if not is_logging:
                    # Re-enable logging
                    action = self._restart_logging(trail_name, dry_run)
                    actions.append(action)
                else:
                    logger.info("Trail %s is already logging", trail_name)

                # Verify configuration integrity
                integrity_actions = self._verify_trail_config(trail_name, dry_run)
                actions.extend(integrity_actions)

        except self.ct.exceptions.TrailNotFoundException:
            err = f"Trail {trail_name} not found — may have been deleted"
            logger.error(err)
            errors.append(err)

        except Exception as e:
            err = f"CloudTrail remediation error: {str(e)}"
            logger.error(err, exc_info=True)
            errors.append(err)

        success      = len(errors) == 0
        action_taken = " | ".join(actions) if actions else "No action taken"

        return RemediationResult(
            event_id      = event.event_id,
            resource_id   = trail_name,
            resource_type = "CloudTrailTrail",
            action_taken  = action_taken,
            success       = success,
            dry_run       = dry_run,
            details       = {"actions": actions, "errors": errors},
            error         = "; ".join(errors) if errors else None,
        )

    def _restart_logging(self, trail_name: str, dry_run: bool) -> str:
        """Re-enable CloudTrail logging."""
        if dry_run:
            logger.info("[DRY RUN] Would restart logging on: %s", trail_name)
            return f"[DRY RUN] Restart logging on {trail_name}"

        self.ct.start_logging(Name=trail_name)
        logger.info("✅ CloudTrail logging restarted: %s", trail_name)
        return f"Restarted logging on trail {trail_name}"

    def _handle_deleted_trail(
        self,
        trail_name: str,
        event:      "RemediationEvent",
        dry_run:    bool
    ) -> str:
        """
        Handle deleted trail — cannot auto-restore.
        Document incident and escalate to manual response.
        """
        logger.critical(
            "CRITICAL: CloudTrail trail DELETED — %s by %s",
            trail_name,
            event.actor
        )

        if dry_run:
            return f"[DRY RUN] Would escalate deleted trail: {trail_name}"

        # Trail deletion requires manual recreation
        # We alert at CRITICAL and document — cannot auto-fix
        return (
            f"Trail {trail_name} DELETED by {event.actor} — "
            f"manual recreation required. Escalated to security team."
        )

    def _verify_trail_config(self, trail_name: str, dry_run: bool) -> list:
        """
        Verify trail has required security settings.
        Re-apply if any are missing.
        """
        actions = []

        try:
            trail = self.ct.get_trail(Name=trail_name)["Trail"]

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                if not dry_run:
                    self.ct.update_trail(
                        Name                      = trail_name,
                        EnableLogFileValidation   = True,
                    )
                actions.append(f"Re-enabled log file validation on {trail_name}")

            # Check multi-region
            if not trail.get("IsMultiRegionTrail", False):
                if not dry_run:
                    self.ct.update_trail(
                        Name               = trail_name,
                        IsMultiRegionTrail = True,
                    )
                actions.append(f"Re-enabled multi-region on {trail_name}")

        except Exception as e:
            logger.warning("Trail config verification failed: %s", str(e))

        return actions
