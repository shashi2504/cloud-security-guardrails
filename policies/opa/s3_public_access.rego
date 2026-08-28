# Blocks S3 buckets with public access enabled, unless the bucket is
# explicitly tagged PublicAccess = "intentional".
#
# Neither tfsec nor Checkov can express this conditional: they either flag
# every public bucket (so teams blanket-suppress the rule and lose the
# signal) or they don't. Requiring an explicit opt-in tag keeps the
# detection while allowing legitimate public buckets — static sites,
# public datasets — to pass with an auditable marker.

package guardrails.s3

import rego.v1

resources := input.planned_values.root_module.resources

# A PAB resource that disables any of the four protections
weak_pab contains pab if {
	some pab in resources
	pab.type == "aws_s3_bucket_public_access_block"
	some setting in [
		pab.values.block_public_acls,
		pab.values.block_public_policy,
		pab.values.ignore_public_acls,
		pab.values.restrict_public_buckets,
	]
	setting == false
}

# Bucket names carrying the opt-in tag
intentional_buckets contains name if {
	some r in resources
	r.type == "aws_s3_bucket"
	r.values.tags_all.PublicAccess == "intentional"
	name := r.values.bucket
}

deny contains msg if {
	some pab in weak_pab
	not pab.values.bucket in intentional_buckets
	msg := sprintf(
		"%s disables public access protection on bucket %q without tag PublicAccess=intentional",
		[pab.address, pab.values.bucket],
	)
}
