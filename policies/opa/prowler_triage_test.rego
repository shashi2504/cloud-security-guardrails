package guardrails.prowler_test

import rego.v1

import data.guardrails.prowler

f(rid, sev) := {"tool": "prowler", "rule_id": rid, "message": "m", "resource": "r", "severity": sev}

test_explicit_block_list_gates if {
	count(prowler.deny) == 1 with input as {"findings": [f("s3_bucket_public_access", "Critical")]}
}

test_account_posture_does_not_gate if {
	count(prowler.deny) == 0 with input as {"findings": [f("iam_root_hardware_mfa_enabled", "Critical")]}
}

# Severity fallback must not override the posture exemption
test_critical_posture_still_does_not_gate if {
	count(prowler.deny) == 0 with input as {"findings": [f("iam_user_hardware_mfa_enabled", "Critical")]}
}

test_high_severity_unlisted_check_gates if {
	count(prowler.deny) == 1 with input as {"findings": [f("some_new_high_check", "High")]}
}

test_medium_severity_warns if {
	count(prowler.deny) == 0 with input as {"findings": [f("some_new_medium_check", "Medium")]}
}

test_no_severity_no_rule_fails_closed if {
	count(prowler.deny) == 1 with input as {"findings": [f("unknown_check", "")]}
}

test_pattern_family_warns_despite_high if {
	count(prowler.deny) == 0 with input as {"findings": [f("ec2_ebs_volume_snapshots_exists", "High")]}
}

test_non_prowler_findings_ignored if {
	count(prowler.deny) == 0 with input as {"findings": [
		{"tool": "checkov", "rule_id": "CKV_AWS_24", "message": "m", "resource": "r", "severity": ""},
	]}
}
