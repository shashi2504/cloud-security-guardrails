"""
S3 Remediator
Fixes S3 misconfiguration automatically:
  - Blocks public access (all 4 settings)
  - Re-enforces bucket policy SSL-only
  - Enables encryption if missing
  - Enables versioning if disabled
"""

import boto3
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_engine import RemediationEvent, RemediationResult

logger = logging.getLogger(__name__)


class S3Remediator:

    def __init__(self, project_name: str):
        self.project_name = project_name
        self.s3           = boto3.client("s3")

    def remediate(
        self,
        event:   "RemediationEvent",
        dry_run: bool = False
    ) -> "RemediationResult":
        """
        Dispatch to correct S3 fix based on event name.
        All fixes run in sequence — belt and suspenders.
        """
        from remediation_engine import RemediationResult

        bucket_name = event.resource_id
        actions     = []
        errors      = []

        logger.info("S3 remediation — bucket: %s | event: %s", bucket_name, event.event_name)

        # Run all applicable fixes
        fixers = [
            self._block_public_access,
            self._enforce_ssl_policy,
            self._enable_encryption,
            self._enable_versioning,
        ]

        for fixer in fixers:
            try:
                action = fixer(bucket_name, dry_run)
                if action:
                    actions.append(action)
            except Exception as e:
                err = f"{fixer.__name__}: {str(e)}"
                logger.error("S3 fix failed — %s", err)
                errors.append(err)

        success      = len(errors) == 0
        action_taken = " | ".join(actions) if actions else "No action taken"

        return RemediationResult(
            event_id      = event.event_id,
            resource_id   = bucket_name,
            resource_type = "S3Bucket",
            action_taken  = action_taken,
            success       = success,
            dry_run       = dry_run,
            details       = {
                "actions": actions,
                "errors":  errors,
                "bucket":  bucket_name,
            },
            error = "; ".join(errors) if errors else None,
        )

    # ─────────────────────────────────────────────────
    # FIX 1 — Block all public access
    # ─────────────────────────────────────────────────

    def _block_public_access(self, bucket: str, dry_run: bool) -> str:
        """
        Enable all 4 public access block settings.
        This is the most critical S3 security control.
        """
        if dry_run:
            logger.info("[DRY RUN] Would block public access on: %s", bucket)
            return f"[DRY RUN] Block public access on {bucket}"

        self.s3.put_public_access_block(
            Bucket                          = bucket,
            PublicAccessBlockConfiguration  = {
                "BlockPublicAcls":        True,
                "IgnorePublicAcls":       True,
                "BlockPublicPolicy":      True,
                "RestrictPublicBuckets":  True,
            }
        )

        logger.info("✅ Public access blocked on: %s", bucket)
        return f"Blocked public access on {bucket}"

    # ─────────────────────────────────────────────────
    # FIX 2 — Enforce SSL-only bucket policy
    # ─────────────────────────────────────────────────

    def _enforce_ssl_policy(self, bucket: str, dry_run: bool) -> str:
        """
        Add or restore bucket policy that denies HTTP access.
        Merges with existing policy if one exists.
        """
        import json

        # SSL deny statement — must always be present
        ssl_deny_statement = {
            "Sid":       "DenyNonSSLRequests",
            "Effect":    "Deny",
            "Principal": "*",
            "Action":    "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket}",
                f"arn:aws:s3:::{bucket}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }

        # Fetch existing policy
        try:
            existing = self.s3.get_bucket_policy(Bucket=bucket)
            policy   = json.loads(existing["Policy"])
        except self.s3.exceptions.NoSuchBucketPolicy:
            policy = {"Version": "2012-10-17", "Statement": []}

        # Check if SSL statement already exists
        ssl_exists = any(
            s.get("Sid") == "DenyNonSSLRequests"
            for s in policy.get("Statement", [])
        )

        if ssl_exists:
            logger.info("SSL policy already present on: %s", bucket)
            return None    # No change needed

        if dry_run:
            logger.info("[DRY RUN] Would enforce SSL policy on: %s", bucket)
            return f"[DRY RUN] Enforce SSL policy on {bucket}"

        # Add SSL deny statement
        policy["Statement"].append(ssl_deny_statement)

        self.s3.put_bucket_policy(
            Bucket = bucket,
            Policy = json.dumps(policy),
        )

        logger.info("✅ SSL policy enforced on: %s", bucket)
        return f"Enforced SSL-only policy on {bucket}"

    # ─────────────────────────────────────────────────
    # FIX 3 — Enable KMS encryption
    # ─────────────────────────────────────────────────

    def _enable_encryption(self, bucket: str, dry_run: bool) -> str:
        """
        Check if bucket has KMS encryption.
        Apply if missing — but don't override existing KMS config.
        """
        try:
            enc = self.s3.get_bucket_encryption(Bucket=bucket)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

            for rule in rules:
                default = rule.get("ApplyServerSideEncryptionByDefault", {})
                if default.get("SSEAlgorithm") == "aws:kms":
                    logger.info("KMS encryption already enabled on: %s", bucket)
                    return None    # Already encrypted with KMS

        except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            pass    # No encryption — apply it
        except Exception:
            pass

        if dry_run:
            logger.info("[DRY RUN] Would enable AES256 encryption on: %s", bucket)
            return f"[DRY RUN] Enable encryption on {bucket}"

        # Apply AES256 as minimum — better than nothing
        # KMS key enforcement is handled by bucket policy (DenyWrongKMSKey)
        self.s3.put_bucket_encryption(
            Bucket = bucket,
            ServerSideEncryptionConfiguration = {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": True,
                }]
            }
        )

        logger.info("✅ Encryption enabled on: %s", bucket)
        return f"Enabled encryption on {bucket}"

    # ─────────────────────────────────────────────────
    # FIX 4 — Enable versioning
    # ─────────────────────────────────────────────────

    def _enable_versioning(self, bucket: str, dry_run: bool) -> str:
        """Enable versioning if suspended or never enabled."""
        versioning = self.s3.get_bucket_versioning(Bucket=bucket)
        status     = versioning.get("Status", "")

        if status == "Enabled":
            return None    # Already on

        if dry_run:
            logger.info("[DRY RUN] Would enable versioning on: %s", bucket)
            return f"[DRY RUN] Enable versioning on {bucket}"

        self.s3.put_bucket_versioning(
            Bucket                  = bucket,
            VersioningConfiguration = {"Status": "Enabled"}
        )

        logger.info("✅ Versioning enabled on: %s", bucket)
        return f"Enabled versioning on {bucket}"
