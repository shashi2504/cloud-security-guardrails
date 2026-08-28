# Classifies raw scanner findings using the triage table in docs/triage.md,
# extracted to triage.json. The markdown table is the source of truth; this
# policy is what makes it executable rather than documentation.
#
# Unknown rule IDs fail closed: a scanner version bump that introduces new
# checks surfaces them for classification instead of passing silently.

package guardrails.triage

import rego.v1

findings := object.get(input, "findings", [])

classify(rule_id) := cls if {
	cls := data.triage[rule_id].class
} else := "UNCLASSIFIED"

blocking contains f if {
	some f in findings
	classify(f.rule_id) == "BLOCK"
}

advisory contains f if {
	some f in findings
	classify(f.rule_id) == "WARN"
}

suppressed contains f if {
	some f in findings
	classify(f.rule_id) == "IGNORE"
}

unclassified contains f if {
	some f in findings
	classify(f.rule_id) == "UNCLASSIFIED"
}

deny contains msg if {
	some f in blocking
	msg := sprintf("BLOCK [%s] %s (%s)", [f.rule_id, f.message, f.resource])
}

deny contains msg if {
	some f in unclassified
	msg := sprintf("UNCLASSIFIED [%s] not in triage table — classify before merge", [f.rule_id])
}

summary := {
	"blocking": count(blocking),
	"advisory": count(advisory),
	"suppressed": count(suppressed),
	"unclassified": count(unclassified),
}
