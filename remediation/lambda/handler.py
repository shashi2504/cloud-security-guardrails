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
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

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


def remediate_public_bucket(s3, bucket: str, tags: dict, enforce: bool) -> dict:
    """Re-enable all four public access block settings on a bucket.

    Reversible, no data loss, no downtime. The bucket stays readable to
    anything with legitimate IAM permissions; only anonymous and
    cross-account public access is closed.
    """
    permitted, reason = tags_permit_remediation(tags)
    action = {
        "action": "PutPublicAccessBlock",
        "resource": bucket,
        "params": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }

    if not permitted:
        log.warning("SKIP %s: %s", bucket, reason)
        return {**action, "status": "skipped", "reason": reason}

    if not enforce:
        log.info("DRY-RUN would call PutPublicAccessBlock on %s", bucket)
        return {**action, "status": "dry-run", "reason": "ENFORCE is not true"}

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=action["params"],
    )
    log.warning("REMEDIATED %s: public access blocked", bucket)
    return {**action, "status": "remediated", "reason": reason}


def open_admin_rules(permissions: list) -> list:
    """Return only the ingress rules exposing 22 or 3389 to 0.0.0.0/0.

    Revoking the whole group would remove legitimate rules alongside the
    dangerous one, so each offending rule is revoked individually.
    """
    admin_ports = {22, 3389}
    offending = []

    for perm in permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if from_port is None or to_port is None:
            continue

        exposed = [
            r for r in perm.get("IpRanges", [])
            if r.get("CidrIp") == "0.0.0.0/0"
        ]
        if not exposed:
            continue

        if any(from_port <= p <= to_port for p in admin_ports):
            offending.append({
                "IpProtocol": perm["IpProtocol"],
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": exposed,
            })

    return offending


def remediate_open_security_group(ec2, group_id: str, permissions: list,
                                  tags: dict, enforce: bool) -> dict:
    """Revoke 0.0.0.0/0 ingress on administrative ports only.

    This does interrupt existing connections on those ports, which is why it
    is tag-gated rather than applied account-wide.
    """
    permitted, reason = tags_permit_remediation(tags)
    offending = open_admin_rules(permissions)

    action = {
        "action": "RevokeSecurityGroupIngress",
        "resource": group_id,
        "params": {"IpPermissions": offending},
    }

    if not offending:
        return {**action, "status": "no-op", "reason": "no admin ports open to 0.0.0.0/0"}

    if not permitted:
        log.warning("SKIP %s: %s", group_id, reason)
        return {**action, "status": "skipped", "reason": reason}

    if not enforce:
        log.info("DRY-RUN would revoke %d rule(s) on %s", len(offending), group_id)
        return {**action, "status": "dry-run", "reason": "ENFORCE is not true"}

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=offending)
    log.warning("REMEDIATED %s: revoked %d rule(s)", group_id, len(offending))
    return {**action, "status": "remediated", "reason": reason}


def tag_as_remediated(client, resource_type: str, identifier: str) -> None:
    """Record that this resource was changed outside Terraform.

    The Terraform still describes the insecure state; the next apply would
    reintroduce it. Tagging makes that drift visible instead of silent.
    """
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tags = [
        {"Key": "RemediatedAt", "Value": stamp},
        {"Key": "RemediatedBy", "Value": "csg-auto-remediation"},
    ]

    if resource_type == "security-group":
        client.create_tags(Resources=[identifier], Tags=tags)
    elif resource_type == "bucket":
        existing = client.get_bucket_tagging(Bucket=identifier).get("TagSet", [])
        keep = [t for t in existing if t["Key"] not in {"RemediatedAt", "RemediatedBy"}]
        client.put_bucket_tagging(
            Bucket=identifier,
            Tagging={"TagSet": keep + tags},
        )


def bucket_tags(s3, bucket: str) -> dict:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchTagSet":
            return {}
        raise
    return {t["Key"]: t["Value"] for t in tag_set}


def lambda_handler(event, context):
    """Entry point. Dispatches on the CloudTrail event name."""
    enforce = enforcing()
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    log.info("event=%s enforce=%s", event_name, enforce)

    s3 = boto3.client("s3")
    ec2 = boto3.client("ec2")

    if event_name in {"PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock"}:
        bucket = detail.get("requestParameters", {}).get("bucketName")
        if not bucket:
            return {"status": "ignored", "reason": "no bucket in event"}

        tags = bucket_tags(s3, bucket)
        result = remediate_public_bucket(s3, bucket, tags, enforce)
        if result["status"] == "remediated":
            tag_as_remediated(s3, "bucket", bucket)
        return result

    if event_name == "AuthorizeSecurityGroupIngress":
        group_id = detail.get("requestParameters", {}).get("groupId")
        if not group_id:
            return {"status": "ignored", "reason": "no group id in event"}

        described = ec2.describe_security_groups(GroupIds=[group_id])
        group = described["SecurityGroups"][0]
        tags = {t["Key"]: t["Value"] for t in group.get("Tags", [])}

        result = remediate_open_security_group(
            ec2, group_id, group.get("IpPermissions", []), tags, enforce
        )
        if result["status"] == "remediated":
            tag_as_remediated(ec2, "security-group", group_id)
        return result

    return {"status": "ignored", "reason": f"unhandled event {event_name}"}
