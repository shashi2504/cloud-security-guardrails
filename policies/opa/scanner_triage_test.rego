package guardrails.triage_test

import rego.v1

import data.guardrails.triage

table := {
	"CKV_AWS_24": {"class": "BLOCK"},
	"CKV_AWS_18": {"class": "WARN"},
	"CKV_AWS_144": {"class": "IGNORE"},
}

finding(rid) := {"rule_id": rid, "message": "m", "resource": "r"}

test_block_produces_denial if {
	count(triage.deny) == 1 with input as {"findings": [finding("CKV_AWS_24")]}
		with data.triage as table
}

test_warn_produces_no_denial if {
	count(triage.deny) == 0 with input as {"findings": [finding("CKV_AWS_18")]}
		with data.triage as table
}

test_ignore_produces_no_denial if {
	count(triage.deny) == 0 with input as {"findings": [finding("CKV_AWS_144")]}
		with data.triage as table
}

test_unknown_rule_fails_closed if {
	count(triage.deny) == 1 with input as {"findings": [finding("CKV_AWS_9999")]}
		with data.triage as table
}

test_summary_counts_each_class if {
	s := triage.summary with input as {"findings": [
		finding("CKV_AWS_24"),
		finding("CKV_AWS_18"),
		finding("CKV_AWS_144"),
		finding("CKV_AWS_9999"),
	]}
		with data.triage as table

	s == {"blocking": 1, "advisory": 1, "suppressed": 1, "unclassified": 1}
}
