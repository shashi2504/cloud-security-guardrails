"""
Security Group Remediator
Removes dangerous ingress rules automatically:
  - SSH (22) open to 0.0.0.0/0
  - RDP (3389) open to 0.0.0.0/0
  - Any port open to 0.0.0.0/0 via protocol -1
"""

import boto3
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from remediation_engine import RemediationEvent, RemediationResult

logger = logging.getLogger(__name__)

# CIDRs that are never allowed as ingress sources
FORBIDDEN_CIDRS = {"0.0.0.0/0", "::/0"}

# Ports that must never be open to forbidden CIDRs
SENSITIVE_PORTS = {
    22:   "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}


class SGRemediator:

    def __init__(self, project_name: str):
        self.project_name = project_name
        self.ec2          = boto3.client("ec2")

    def remediate(
        self,
        event:   "RemediationEvent",
        dry_run: bool = False
    ) -> "RemediationResult":
        """Find and remove all dangerous ingress rules."""
        from remediation_engine import RemediationResult

        sg_id   = event.resource_id
        actions = []
        errors  = []

        logger.info("SG remediation — sg: %s | event: %s", sg_id, event.event_name)

        try:
            # Fetch current rules
            response = self.ec2.describe_security_groups(GroupIds=[sg_id])
            if not response["SecurityGroups"]:
                raise ValueError(f"Security group {sg_id} not found")

            sg           = response["SecurityGroups"][0]
            ingress_rules = sg.get("IpPermissions", [])
            sg_name       = sg.get("GroupName", sg_id)

            # Find dangerous rules
            bad_rules = self._find_dangerous_rules(ingress_rules)

            if not bad_rules:
                logger.info("No dangerous rules found on: %s", sg_id)
                return RemediationResult(
                    event_id      = event.event_id,
                    resource_id   = sg_id,
                    resource_type = "SecurityGroup",
                    action_taken  = "No dangerous rules found",
                    success       = True,
                    dry_run       = dry_run,
                    details       = {"sg_name": sg_name, "rules_checked": len(ingress_rules)},
                )

            # Revoke each dangerous rule
            for rule in bad_rules:
                try:
                    action = self._revoke_rule(sg_id, rule, dry_run)
                    actions.append(action)
                except Exception as e:
                    err = f"Failed to revoke rule: {str(e)}"
                    logger.error(err)
                    errors.append(err)

        except Exception as e:
            err = f"SG remediation error: {str(e)}"
            logger.error(err, exc_info=True)
            errors.append(err)

        success      = len(errors) == 0
        action_taken = " | ".join(actions) if actions else "No rules revoked"

        return RemediationResult(
            event_id      = event.event_id,
            resource_id   = sg_id,
            resource_type = "SecurityGroup",
            action_taken  = action_taken,
            success       = success,
            dry_run       = dry_run,
            details       = {
                "actions":       actions,
                "errors":        errors,
                "rules_removed": len(actions),
            },
            error = "; ".join(errors) if errors else None,
        )

    def _find_dangerous_rules(self, rules: list) -> list:
        """
        Identify rules that expose sensitive ports or
        allow all traffic from open CIDRs.
        """
        dangerous = []

        for rule in rules:
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort",   65535)
            protocol  = rule.get("IpProtocol", "-1")

            # Collect open CIDRs from this rule
            open_cidrs = []
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") in FORBIDDEN_CIDRS:
                    open_cidrs.append(ip_range["CidrIp"])

            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") in FORBIDDEN_CIDRS:
                    open_cidrs.append(ip_range["CidrIpv6"])

            if not open_cidrs:
                continue    # No open CIDRs in this rule — safe

            # Protocol -1 = all traffic — always dangerous
            if protocol == "-1":
                dangerous.append({
                    "rule":       rule,
                    "reason":     "All traffic allowed from open CIDR",
                    "open_cidrs": open_cidrs,
                })
                continue

            # Check sensitive port ranges
            for port, service in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    dangerous.append({
                        "rule":       rule,
                        "reason":     f"{service} port {port} open to internet",
                        "open_cidrs": open_cidrs,
                        "port":       port,
                        "service":    service,
                    })
                    break

        logger.info("Found %d dangerous rules", len(dangerous))
        return dangerous

    def _revoke_rule(self, sg_id: str, dangerous: dict, dry_run: bool) -> str:
        """Revoke a single dangerous ingress rule."""
        rule    = dangerous["rule"]
        reason  = dangerous["reason"]
        port    = dangerous.get("port", "all")
        service = dangerous.get("service", "all traffic")

        if dry_run:
            logger.info(
                "[DRY RUN] Would revoke rule — SG: %s | Reason: %s",
                sg_id, reason
            )
            return f"[DRY RUN] Revoke {reason} on {sg_id}"

        self.ec2.revoke_security_group_ingress(
            GroupId        = sg_id,
            IpPermissions  = [rule],
        )

        logger.info(
            "✅ Revoked rule — SG: %s | Port: %s | Reason: %s",
            sg_id, port, reason
        )
        return f"Revoked {service} open ingress from {sg_id}"
