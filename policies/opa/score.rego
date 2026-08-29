# Security scoring.
#
# Three design decisions, each a consequence of something observed while
# building this:
#
# 1. Not passed-over-total. Three checks passed on a world-readable bucket
#    because they tested conditions that did not apply. Vacuous passes
#    inflate any ratio-based score.
#
# 2. Deduplicated by (resource, condition). One public bucket produced nine
#    findings across two scanners. Scoring each separately measures how many
#    overlapping rules the tools ship, not how exposed the account is.
#
# 3. UNCLASSIFIED carries weight. An unrecognised finding is unmeasured
#    risk. If unknown rules scored zero, the score would improve every time
#    scanner coverage grew.
#
# Weights come from this project's own BLOCK/WARN/IGNORE classification,
# not from vendor severity ratings.

package guardrails.score

import rego.v1

import data.guardrails.prowler.scope

all_findings := object.get(input, "findings", [])

# The code score covers static IaC scanners. Prowler findings are runtime
# observations classified by guardrails.prowler, not by the triage table,
# so scoring them here would apply the wrong classifier to a third of the
# input and inflate the unclassified count.
findings contains f if {
	some f in all_findings
	f.tool in {"tfsec", "checkov"}
}

prowler_findings contains f if {
	some f in all_findings
	f.tool == "prowler"
}

classify(rule_id) := cls if {
	cls := data.triage[rule_id].class
} else := "UNCLASSIFIED"

condition_of(rule_id) := c if {
	c := data.conditions[rule_id]
} else := sprintf("rule:%s", [rule_id])

weights := {
	"s3_public_access": 25,
	"open_admin_port": 20,
	"iam_full_admin": 20,
	"iam_privilege_escalation": 20,
	"iam_permissions_management": 15,
	"unencrypted_storage": 15,
}

# One entry per distinct (resource, condition) pair.
blocking_exposures contains [f.resource, condition_of(f.rule_id)] if {
	some f in findings
	not scope.is_account_posture(f.rule_id)
	classify(f.rule_id) == "BLOCK"
}

advisory_findings contains [f.resource, f.rule_id] if {
	some f in findings
	not scope.is_account_posture(f.rule_id)
	classify(f.rule_id) == "WARN"
}

unclassified_findings contains [f.resource, f.rule_id] if {
	some f in findings
	not scope.is_account_posture(f.rule_id)
	classify(f.rule_id) == "UNCLASSIFIED"
}

posture_findings contains [f.resource, f.rule_id] if {
	some f in prowler_findings
	scope.is_account_posture(f.rule_id)
}

weight_of(condition) := w if {
	w := weights[condition]
} else := 15

blocking_penalty := sum([w |
	some [_, condition] in blocking_exposures
	w := weight_of(condition)
])

advisory_penalty := count(advisory_findings) * 3

unclassified_penalty := count(unclassified_findings) * 10

total_penalty := blocking_penalty + advisory_penalty + unclassified_penalty

code_score := s if {
	s := 100 - min([100, total_penalty])
}

# Account posture is scored separately: no pull request can fix root MFA,
# so blending it into the code score hides which of the two is failing.
#
# Reported as null when no CSPM scan is present. A perfect score for an
# account nobody audited would be absence of evidence dressed up as
# evidence of absence.
#
# The penalty is capped rather than linear: posture findings are unbounded
# hygiene items, and 24 of them does not mean "maximally compromised".
account_score := null if {
	count(prowler_findings) == 0
} else := s if {
	s := 100 - min([60, count(posture_findings) * 2])
}

report := {
	"code_score": code_score,
	"account_score": account_score,
	"distinct_exposures": count(blocking_exposures),
	"advisory_count": count(advisory_findings),
	"unclassified_count": count(unclassified_findings),
	"posture_count": count(posture_findings),
	"raw_finding_count": count(all_findings),
	"scanned_by_cspm": count(prowler_findings) > 0,
}
