package guardrails.score_test

import rego.v1

import data.guardrails.score

table := {
	"CKV_AWS_53": {"class": "BLOCK"},
	"CKV_AWS_54": {"class": "BLOCK"},
	"CKV_AWS_70": {"class": "BLOCK"},
	"CKV_AWS_24": {"class": "BLOCK"},
	"CKV_AWS_18": {"class": "WARN"},
	"CKV_AWS_144": {"class": "IGNORE"},
}

conds := {
	"CKV_AWS_53": "s3_public_access",
	"CKV_AWS_54": "s3_public_access",
	"CKV_AWS_70": "s3_public_access",
	"CKV_AWS_24": "open_admin_port",
}

f(rid, res) := {"tool": "checkov", "rule_id": rid, "message": "m", "resource": res, "severity": ""}

test_clean_scores_100 if {
	r := score.report with input as {"findings": []}
		with data.triage as table
		with data.conditions as conds
	r.code_score == 100
}

# Three rules, one bucket, one condition — one exposure, not three.
test_dedups_overlapping_rules if {
	r := score.report with input as {"findings": [
		f("CKV_AWS_53", "bucket-a"),
		f("CKV_AWS_54", "bucket-a"),
		f("CKV_AWS_70", "bucket-a"),
	]}
		with data.triage as table
		with data.conditions as conds

	r.distinct_exposures == 1
	r.raw_finding_count == 3
	r.code_score == 75
}

# Same condition on two buckets is two exposures.
test_same_condition_different_resources_counts_twice if {
	r := score.report with input as {"findings": [
		f("CKV_AWS_53", "bucket-a"),
		f("CKV_AWS_53", "bucket-b"),
	]}
		with data.triage as table
		with data.conditions as conds
	r.distinct_exposures == 2
	r.code_score == 50
}

test_ignore_class_scores_zero if {
	r := score.report with input as {"findings": [f("CKV_AWS_144", "bucket-a")]}
		with data.triage as table
		with data.conditions as conds
	r.code_score == 100
}

test_unclassified_costs_more_than_advisory if {
	r := score.report with input as {"findings": [f("CKV_AWS_9999", "bucket-a")]}
		with data.triage as table
		with data.conditions as conds
	r.code_score == 90
	r.unclassified_count == 1
}

test_posture_excluded_from_code_score if {
	r := score.report with input as {"findings": [
		{"tool": "prowler", "rule_id": "iam_root_hardware_mfa_enabled", "message": "m", "resource": "root", "severity": "Critical"},
	]}
		with data.triage as table
		with data.conditions as conds

	r.code_score == 100
	r.account_score == 98
	r.posture_count == 1
}

test_score_floors_at_zero if {
	r := score.report with input as {"findings": [
		f("CKV_AWS_53", "b1"), f("CKV_AWS_53", "b2"), f("CKV_AWS_53", "b3"),
		f("CKV_AWS_53", "b4"), f("CKV_AWS_53", "b5"),
	]}
		with data.triage as table
		with data.conditions as conds
	r.code_score == 0
}

test_account_score_null_without_cspm_scan if {
	r := score.report with input as {"findings": [f("CKV_AWS_53", "bucket-a")]}
		with data.triage as table
		with data.conditions as conds
	r.account_score == null
	r.scanned_by_cspm == false
}
