# Environment-aware severity gating.
#
# The environment is supplied by the CI job (opa eval --data), never read
# from resource tags. If the code under evaluation could declare its own
# environment, a PR could downgrade its own findings by editing one line,
# and the gate would be advisory rather than enforcing.

package guardrails.severity

import rego.v1

env := object.get(input, "environment", "prod")

config := data.environments[env]

enforced_categories := object.get(config, "enforce", [])

warned_categories := object.get(config, "warn", [])

# Findings arrive as {category, message} from the category policies.
findings := object.get(input, "findings", [])

blocking contains f if {
	some f in findings
	f.category in enforced_categories
}

advisory contains f if {
	some f in findings
	f.category in warned_categories
}

# Unmapped categories fail closed — a new category nobody classified
# blocks rather than silently passing.
unmapped contains f if {
	some f in findings
	not f.category in enforced_categories
	not f.category in warned_categories
}

allow if {
	count(blocking) == 0
	count(unmapped) == 0
}
