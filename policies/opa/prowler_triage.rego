# Prowler classification.
#
# Per-rule classification worked for 40 static-scanner rules. Prowler ships
# ~148 checks for three services alone and hundreds account-wide, so
# hand-classifying every ID does not scale.
#
# Three tiers, in precedence order:
#   1. Explicit block list — checks representing live exposure.
#   2. Pattern families — known-benign categories classified in bulk.
#   3. Severity fallback — Critical/High block, the rest warn.
#
# Severity alone is not sufficient: Prowler rates
# ec2_ebs_volume_snapshots_exists as High, but a missing snapshot is a
# backup concern, not exposure. Vendor severity encodes vendor priorities.

package guardrails.prowler

import rego.v1

import data.guardrails.prowler.scope

# Tier 1 — live exposure. These block regardless of vendor severity.
blocking_checks := {
	"s3_bucket_public_access",
	"s3_bucket_level_public_access_block",
	"s3_account_level_public_access_blocks",
	"s3_bucket_policy_public_write_access",
	"ec2_securitygroup_allow_ingress_from_internet_to_port_22",
	"ec2_securitygroup_allow_ingress_from_internet_to_port_3389",
	"ec2_securitygroup_allow_ingress_from_internet_to_any_port",
	"iam_user_administrator_access_policy",
	"iam_root_hardware_mfa_enabled",
	"ec2_ebs_volume_encryption",
}

# Tier 2 — families classified in bulk, with reasons.
advisory_patterns := {
	"iam_password_policy_": "Password policy strength — real but not exposure; no blast radius today.",
	"_backup_plan": "Availability control, not security.",
	"_snapshots_exists": "Backup concern. Prowler rates High; disagreeing deliberately.",
	"_not_used": "Unused resource hygiene. No attack surface while unattached.",
	"_not_stale_to_": "Service-access staleness. Operational hygiene.",
}

findings contains f if {
	some f in object.get(input, "findings", [])
	f.tool == "prowler"
}

matches_advisory(rule_id) if {
	some pattern, _ in advisory_patterns
	contains(rule_id, pattern)
}

classify(f) := "POSTURE" if {
	scope.is_account_posture(f.rule_id)
} else := "BLOCK" if {
	f.rule_id in blocking_checks
} else := "WARN" if {
	matches_advisory(f.rule_id)
} else := "BLOCK" if {
	f.severity in {"Critical", "High"}
} else := "WARN" if {
	f.severity in {"Medium", "Low", "Informational"}
} else := "UNCLASSIFIED"

blocking contains f if {
	some f in findings
	classify(f) == "BLOCK"
}

advisory contains f if {
	some f in findings
	classify(f) == "WARN"
}

posture contains f if {
	some f in findings
	classify(f) == "POSTURE"
}

unclassified contains f if {
	some f in findings
	classify(f) == "UNCLASSIFIED"
}

deny contains msg if {
	some f in blocking
	msg := sprintf("BLOCK [%s] %s (%s)", [f.rule_id, f.message, f.resource])
}

deny contains msg if {
	some f in unclassified
	msg := sprintf("UNCLASSIFIED [%s] no rule and no severity — classify before merge", [f.rule_id])
}

summary := {
	"blocking": count(blocking),
	"posture": count(posture),
	"advisory": count(advisory),
	"unclassified": count(unclassified),
}
