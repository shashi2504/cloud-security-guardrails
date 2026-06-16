"""
IAM Remediator
Detects and reverses overly permissive IAM changes:
  - Admin policy attached to user
  - Wildcard policy attached
  - New access key created (alerts for rotation)
"""

import boto3
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_engine import RemediationEvent, RemediationResult

logger = logging.getLogger(__name__)

# Policies that should NEVER be directly attached to users
FORBIDDEN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


class IAMRemediator:

    def __init__(self, project_name: str):
        self.project_name = project_name
        self.iam          = boto3.client("iam")

    def remediate(
        self,
        event:   "RemediationEvent",
        dry_run: bool = False
    ) -> "RemediationResult":
        """Route to correct IAM fix."""
        from remediation_engine import RemediationResult

        actions = []
        errors  = []

        logger.info(
            "IAM remediation — resource: %s | event: %s",
            event.resource_id,
            event.event_name
        )

        try:
            if event.event_name in ["AttachUserPolicy", "PutUserPolicy"]:
                action = self._handle_policy_attachment(event, dry_run)
                if action:
                    actions.append(action)

            elif event.event_name == "CreateAccessKey":
                action = self._handle_access_key(event, dry_run)
                if action:
                    actions.append(action)

            elif event.event_name == "AttachRolePolicy":
                action = self._handle_role_policy(event, dry_run)
                if action:
                    actions.append(action)

        except Exception as e:
            err = f"IAM remediation error: {str(e)}"
            logger.error(err, exc_info=True)
            errors.append(err)

        success      = len(errors) == 0
        action_taken = " | ".join(actions) if actions else "No action taken"

        return RemediationResult(
            event_id      = event.event_id,
            resource_id   = event.resource_id,
            resource_type = event.resource_type,
            action_taken  = action_taken,
            success       = success,
            dry_run       = dry_run,
            details       = {"actions": actions, "errors": errors},
            error         = "; ".join(errors) if errors else None,
        )

    def _handle_policy_attachment(
        self,
        event:   "RemediationEvent",
        dry_run: bool
    ) -> str:
        """
        Detach forbidden policies from users.
        Covers both AttachUserPolicy and PutUserPolicy.
        """
        params      = event.raw_event.get("detail", {}).get("requestParameters", {}) or {}
        username    = params.get("userName", event.resource_id)
        policy_arn  = params.get("policyArn", "")

        # Check if attached policy is forbidden
        if policy_arn and policy_arn not in FORBIDDEN_POLICIES:
            # Check if it's a wildcard admin policy
            if not self._is_admin_policy(policy_arn):
                logger.info(
                    "Policy %s on user %s is not forbidden — no action",
                    policy_arn, username
                )
                return None

        if dry_run:
            logger.info(
                "[DRY RUN] Would detach policy %s from user %s",
                policy_arn, username
            )
            return f"[DRY RUN] Detach {policy_arn} from {username}"

        if policy_arn:
            self.iam.detach_user_policy(
                UserName  = username,
                PolicyArn = policy_arn,
            )
            logger.info(
                "✅ Detached forbidden policy %s from user %s",
                policy_arn, username
            )
            return f"Detached forbidden policy {policy_arn} from user {username}"

        return None

    def _handle_access_key(
        self,
        event:   "RemediationEvent",
        dry_run: bool
    ) -> str:
        """
        Alert on new access key creation.
        We don't auto-delete — that could break legitimate automation.
        Escalate to manual review instead.
        """
        params   = event.raw_event.get("detail", {}).get("requestParameters", {}) or {}
        username = params.get("userName", event.resource_id)
        actor    = event.actor

        logger.warning(
            "New access key created for user %s by %s — flagged for review",
            username, actor
        )

        # Return action string — SNS notification handles actual alerting
        return (
            f"FLAGGED: New access key created for {username} by {actor}. "
            f"Verify this is expected and rotate if not."
        )

    def _handle_role_policy(
        self,
        event:   "RemediationEvent",
        dry_run: bool
    ) -> str:
        """
        Check if admin policy attached to a role.
        Detach if forbidden — alert for manual review.
        """
        params     = event.raw_event.get("detail", {}).get("requestParameters", {}) or {}
        role_name  = params.get("roleName", event.resource_id)
        policy_arn = params.get("policyArn", "")

        if policy_arn not in FORBIDDEN_POLICIES:
            return None

        if dry_run:
            return f"[DRY RUN] Detach {policy_arn} from role {role_name}"

        self.iam.detach_role_policy(
            RoleName  = role_name,
            PolicyArn = policy_arn,
        )

        logger.info(
            "✅ Detached forbidden policy %s from role %s",
            policy_arn, role_name
        )
        return f"Detached forbidden policy {policy_arn} from role {role_name}"

    def _is_admin_policy(self, policy_arn: str) -> bool:
        """Check if a managed policy grants admin access."""
        try:
            policy    = self.iam.get_policy(PolicyArn=policy_arn)
            version   = policy["Policy"]["DefaultVersionId"]
            doc       = self.iam.get_policy_version(
                PolicyArn  = policy_arn,
                VersionId  = version
            )
            statements = doc["PolicyVersion"]["Document"].get("Statement", [])

            for stmt in statements:
                if (
                    stmt.get("Effect") == "Allow" and
                    stmt.get("Action") == "*" and
                    stmt.get("Resource") == "*"
                ):
                    return True

            return False

        except Exception as e:
            logger.warning("Could not check policy %s: %s", policy_arn, str(e))
            return False
