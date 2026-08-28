# Finding Triage Policy

Every rule reported by tfsec and Checkov against the vulnerable environment is
classified BLOCK, WARN, IGNORE, or DECIDE.

- BLOCK  - merge fails. Reserved for genuine exposure.
- WARN   - reported in the PR, does not fail the build.
- IGNORE - suppressed. Requires a written justification.
- DECIDE - contested; owner sign-off pending.

**Status:** All 40 rules classified. Four judgment calls settled: ingress blocks
while egress warns (unrestricted egress is the AWS default; blocking it would fail
every PR and get the gate disabled); three IAM checks block (full admin, privilege escalation, permissions
management) while the redundant five warn; customer-managed KMS keys warn (cost/compliance decision, not a
security-vs-insecurity one); access logging warns (detection, not prevention).

| Tool | Rule ID | Severity | Description | Class | Rationale |
|------|---------|----------|-------------|-------|-----------|
| tfsec | aws-ec2-enable-volume-encryption | HIGH | EBS volumes must be encrypted | BLOCK |  |
| tfsec | aws-ec2-no-public-egress-sgr | CRITICAL | An egress security group rule allows traffic to /0. | WARN | CRITICAL per tfsec vs AWS default. Blocks exfil/C2 but may make gate unusable. |
| tfsec | aws-ec2-no-public-ingress-sgr | CRITICAL | An ingress security group rule allows traffic from /0. | BLOCK |  |
| tfsec | aws-ec2-volume-encryption-customer-key | LOW | EBS volume encryption should use Customer Managed Keys | WARN | CMK at $1/key/mo — security requirement or cost decision? |
| tfsec | aws-iam-no-policy-wildcards | HIGH | IAM policy should avoid use of wildcards and instead apply the principle of least privilege | BLOCK |  |
| tfsec | aws-s3-block-public-acls | HIGH | S3 Access block should block public ACL | BLOCK |  |
| tfsec | aws-s3-block-public-policy | HIGH | S3 Access block should block public policy | BLOCK |  |
| tfsec | aws-s3-enable-bucket-encryption | HIGH | Unencrypted S3 bucket. | IGNORE | Stale rule: AWS applies SSE-S3 by default since Jan 2023. Checkov CKV_AWS_19 passes. |
| tfsec | aws-s3-enable-bucket-logging | MEDIUM | S3 Bucket does not have logging enabled. | WARN | Only way to know a public bucket was read. Exposure-adjacent? |
| tfsec | aws-s3-enable-versioning | MEDIUM | S3 Data should be versioned | WARN |  |
| tfsec | aws-s3-encryption-customer-key | HIGH | S3 encryption should use Customer Managed Keys | WARN | CMK at $1/key/mo — security requirement or cost decision? |
| tfsec | aws-s3-ignore-public-acls | HIGH | S3 Access Block should Ignore Public Acl | BLOCK |  |
| tfsec | aws-s3-no-public-buckets | HIGH | S3 Access block should restrict public bucket to limit access | BLOCK |  |
| checkov | CKV_AWS_53 |  | Ensure S3 bucket has block public ACLS enabled | BLOCK |  |
| checkov | CKV_AWS_55 |  | Ensure S3 bucket has ignore public ACLs enabled | BLOCK |  |
| checkov | CKV_AWS_56 |  | Ensure S3 bucket has 'restrict_public_buckets' enabled | BLOCK |  |
| checkov | CKV_AWS_54 |  | Ensure S3 bucket has block public policy enabled | BLOCK |  |
| checkov | CKV_AWS_70 |  | Ensure S3 bucket does not allow an action with any Principal | BLOCK |  |
| checkov | CKV_AWS_25 |  | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 | BLOCK |  |
| checkov | CKV_AWS_382 |  | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | WARN | Same call as tfsec egress rule — must match. |
| checkov | CKV_AWS_24 |  | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | BLOCK |  |
| checkov | CKV_AWS_3 |  | Ensure all data stored in the EBS is securely encrypted | BLOCK |  |
| checkov | CKV_AWS_189 |  | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) | WARN | CMK cost call — must match tfsec CMK rules. |
| checkov | CKV_AWS_290 |  | Ensure IAM policies does not allow write access without constraints | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_287 |  | Ensure IAM policies does not allow credentials exposure | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_288 |  | Ensure IAM policies does not allow data exfiltration | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_355 |  | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_62 |  | Ensure IAM policies that allow full "*-*" administrative privileges are not created | BLOCK |  |
| checkov | CKV_AWS_289 |  | Ensure IAM policies does not allow permissions management / resource exposure without constraints | BLOCK | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_63 |  | Ensure no IAM policies documents allow "*" as a statement's actions | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_286 |  | Ensure IAM policies does not allow privilege escalation | BLOCK | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV2_AWS_5 |  | Ensure that Security Groups are attached to another resource | IGNORE | Test-environment artifact: no EC2 by design. Unattached SG has no attack surface. |
| checkov | CKV2_AWS_62 |  | Ensure S3 buckets should have event notifications enabled | IGNORE | Operational integration, not security. |
| checkov | CKV_AWS_18 |  | Ensure the S3 bucket has access logging enabled | WARN | Same call as tfsec logging rule — must match. |
| checkov | CKV_AWS_144 |  | Ensure that S3 bucket has cross-region replication enabled | IGNORE | Availability/DR control, not security. Real cost, no confidentiality benefit. |
| checkov | CKV2_AWS_61 |  | Ensure that an S3 bucket has a lifecycle configuration | IGNORE | Cost management control, not security. |
| checkov | CKV2_AWS_40 |  | Ensure AWS IAM policy does not allow full IAM privileges | WARN | One of 8 IAM checks on one wildcard. All BLOCK, or 1 BLOCK + 7 WARN? |
| checkov | CKV_AWS_145 |  | Ensure that S3 buckets are encrypted with KMS by default | WARN | CMK cost call — must match tfsec CMK rules. |
| checkov | CKV_AWS_21 |  | Ensure all data stored in the S3 bucket have versioning enabled | WARN |  |
| checkov | CKV2_AWS_6 |  | Ensure that S3 bucket has a Public Access block | BLOCK |  |

## Baseline scan results (vulnerable environment)

- Intentional flaws planted: 4
- tfsec findings: 15 (13 unique rules)
- Checkov failed checks: 27 (27 unique rules)
- Total findings: 42
- Findings per planted flaw: 10.5
- Blocking categories: 5 (19 rule IDs)
- Rows pending decision: 0
- Confirmed false positives: 1 (tfsec aws-s3-enable-bucket-encryption - stale vs AWS SSE-S3 default, Jan 2023)
- Vacuous passes identified: 3 (CKV2_AWS_2, CKV_AWS_20, CKV_AWS_57)
