package guardrails.s3_test

import rego.v1

import data.guardrails.s3

pab(bucket, blocked) := {
	"address": "aws_s3_bucket_public_access_block.test",
	"type": "aws_s3_bucket_public_access_block",
	"values": {
		"bucket": bucket,
		"block_public_acls": blocked,
		"block_public_policy": blocked,
		"ignore_public_acls": blocked,
		"restrict_public_buckets": blocked,
	},
}

bucket(name, tags) := {
	"address": "aws_s3_bucket.test",
	"type": "aws_s3_bucket",
	"values": {"bucket": name, "tags_all": tags},
}

plan(resources) := {"planned_values": {"root_module": {"resources": resources}}}

test_denies_untagged_public_bucket if {
	count(s3.deny) == 1 with input as plan([
		pab("data-bucket", false),
		bucket("data-bucket", {}),
	])
}

test_allows_tagged_public_bucket if {
	count(s3.deny) == 0 with input as plan([
		pab("site-bucket", false),
		bucket("site-bucket", {"PublicAccess": "intentional"}),
	])
}

test_allows_locked_down_bucket if {
	count(s3.deny) == 0 with input as plan([
		pab("private-bucket", true),
		bucket("private-bucket", {}),
	])
}

# Tag on a different bucket must not exempt this one
test_tag_does_not_leak_across_buckets if {
	count(s3.deny) == 1 with input as plan([
		pab("data-bucket", false),
		bucket("data-bucket", {}),
		bucket("site-bucket", {"PublicAccess": "intentional"}),
	])
}
