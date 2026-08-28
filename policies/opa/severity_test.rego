package guardrails.severity_test

import rego.v1

import data.guardrails.severity

envs := {
	"prod": {"enforce": ["public_exposure"], "warn": ["access_logging"]},
	"dev": {"enforce": [], "warn": ["public_exposure", "access_logging"]},
}

test_prod_blocks_public_exposure if {
	not severity.allow with input as {
		"environment": "prod",
		"findings": [{"category": "public_exposure", "message": "x"}],
	}
		with data.environments as envs
}

test_dev_warns_on_same_finding if {
	severity.allow with input as {
		"environment": "dev",
		"findings": [{"category": "public_exposure", "message": "x"}],
	}
		with data.environments as envs
}

test_unmapped_category_fails_closed if {
	not severity.allow with input as {
		"environment": "prod",
		"findings": [{"category": "brand_new_check", "message": "x"}],
	}
		with data.environments as envs
}

test_no_findings_allows if {
	severity.allow with input as {"environment": "prod", "findings": []}
		with data.environments as envs
}

# Absent environment must default to prod, not to permissive
test_missing_environment_defaults_to_prod if {
	not severity.allow with input as {
		"findings": [{"category": "public_exposure", "message": "x"}],
	}
		with data.environments as envs
}
