"""Auto-remediation for public S3 buckets and internet-facing admin ports.

Safety model, in order of evaluation:

1. ENFORCE defaults to false. In dry-run the handler logs the exact API call
   it would make and returns without touching anything.
2. Both required tags must be present on the resource. A resource missing
   either is skipped, logged, and reported. The dev landing zone carries
   AutoRemediate=disabled specifically so this handler cannot touch it.
3. Only two actions are implemented, both reversible:
     - PutPublicAccessBlock on a bucket
     - RevokeSecurityGroupIngress for a specific 0.0.0.0/0 rule
   The blueprint's "snapshot and re-encrypt the EBS volume" flow is not
   implemented: it requires stopping the instance, which is an outage
   rather than a remediation.

Remediation fixes the live resource, not the Terraform that created it. Every
remediated resource is tagged RemediatedAt/RemediatedBy so the drift is
visible rather than silent, and the fix is temporary until the IaC is
corrected.
"""

import logging
import os

logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

REQUIRED_TAGS = {
    "AutoRemediate": "enabled",
    "Project": "cloud-security-guardrails",
}


def enforcing() -> bool:
    return os.environ.get("ENFORCE", "false").lower() == "true"


def tags_permit_remediation(tags: dict) -> tuple[bool, str]:
    """Both required tags must match exactly.

    Returns (permitted, reason). The reason is logged and returned in the
    response so a skipped resource is visible rather than silently ignored.
    """
    if not tags:
        return False, "resource has no tags"

    for key, expected in REQUIRED_TAGS.items():
        actual = tags.get(key)
        if actual is None:
            return False, f"missing required tag {key}"
        if actual != expected:
            return False, f"tag {key}={actual}, requires {expected}"

    return True, "all required tags present"
