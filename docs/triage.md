# Finding Triage Policy

Every rule reported by tfsec and Checkov against the vulnerable environment is
classified BLOCK, WARN, or IGNORE.

- BLOCK  - merge fails. Reserved for genuine exposure.
- WARN   - reported in the PR, does not fail the build.
- IGNORE - suppressed. Requires a written justification.

| Tool | Rule ID | Severity | Description | Class | Rationale |
|------|---------|----------|-------------|-------|-----------|
| tfsec | aws-ec2-enable-volume-encryption | HIGH | EBS volumes must be encrypted |  |  |
| tfsec | aws-ec2-no-public-egress-sgr | CRITICAL | An egress security group rule allows traffic to /0. |  |  |
| tfsec | aws-ec2-no-public-ingress-sgr | CRITICAL | An ingress security group rule allows traffic from /0. |  |  |
| tfsec | aws-ec2-volume-encryption-customer-key | LOW | EBS volume encryption should use Customer Managed Keys |  |  |
| tfsec | aws-iam-no-policy-wildcards | HIGH | IAM policy should avoid use of wildcards and instead apply the principle of least privilege |  |  |
| tfsec | aws-s3-block-public-acls | HIGH | S3 Access block should block public ACL |  |  |
| tfsec | aws-s3-block-public-policy | HIGH | S3 Access block should block public policy |  |  |
| tfsec | aws-s3-enable-bucket-encryption | HIGH | Unencrypted S3 bucket. |  |  |
| tfsec | aws-s3-enable-bucket-logging | MEDIUM | S3 Bucket does not have logging enabled. |  |  |
| tfsec | aws-s3-enable-versioning | MEDIUM | S3 Data should be versioned |  |  |
| tfsec | aws-s3-encryption-customer-key | HIGH | S3 encryption should use Customer Managed Keys |  |  |
| tfsec | aws-s3-ignore-public-acls | HIGH | S3 Access Block should Ignore Public Acl |  |  |
| tfsec | aws-s3-no-public-buckets | HIGH | S3 Access block should restrict public bucket to limit access |  |  |
| checkov | CKV_AWS_53 |  | Ensure S3 bucket has block public ACLS enabled |  |  |
| checkov | CKV_AWS_55 |  | Ensure S3 bucket has ignore public ACLs enabled |  |  |
| checkov | CKV_AWS_56 |  | Ensure S3 bucket has 'restrict_public_buckets' enabled |  |  |
| checkov | CKV_AWS_54 |  | Ensure S3 bucket has block public policy enabled |  |  |
| checkov | CKV_AWS_70 |  | Ensure S3 bucket does not allow an action with any Principal |  |  |
| checkov | CKV_AWS_25 |  | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 |  |  |
| checkov | CKV_AWS_382 |  | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 |  |  |
| checkov | CKV_AWS_24 |  | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |  |  |
| checkov | CKV_AWS_3 |  | Ensure all data stored in the EBS is securely encrypted |  |  |
| checkov | CKV_AWS_189 |  | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) |  |  |
| checkov | CKV_AWS_290 |  | Ensure IAM policies does not allow write access without constraints |  |  |
| checkov | CKV_AWS_287 |  | Ensure IAM policies does not allow credentials exposure |  |  |
| checkov | CKV_AWS_288 |  | Ensure IAM policies does not allow data exfiltration |  |  |
| checkov | CKV_AWS_355 |  | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |  |  |
| checkov | CKV_AWS_62 |  | Ensure IAM policies that allow full "*-*" administrative privileges are not created |  |  |
| checkov | CKV_AWS_289 |  | Ensure IAM policies does not allow permissions management / resource exposure without constraints |  |  |
| checkov | CKV_AWS_63 |  | Ensure no IAM policies documents allow "*" as a statement's actions |  |  |
| checkov | CKV_AWS_286 |  | Ensure IAM policies does not allow privilege escalation |  |  |
| checkov | CKV2_AWS_5 |  | Ensure that Security Groups are attached to another resource |  |  |
| checkov | CKV2_AWS_62 |  | Ensure S3 buckets should have event notifications enabled |  |  |
| checkov | CKV_AWS_18 |  | Ensure the S3 bucket has access logging enabled |  |  |
| checkov | CKV_AWS_144 |  | Ensure that S3 bucket has cross-region replication enabled |  |  |
| checkov | CKV2_AWS_61 |  | Ensure that an S3 bucket has a lifecycle configuration |  |  |
| checkov | CKV2_AWS_40 |  | Ensure AWS IAM policy does not allow full IAM privileges |  |  |
| checkov | CKV_AWS_145 |  | Ensure that S3 buckets are encrypted with KMS by default |  |  |
| checkov | CKV_AWS_21 |  | Ensure all data stored in the S3 bucket have versioning enabled |  |  |
| checkov | CKV2_AWS_6 |  | Ensure that S3 bucket has a Public Access block |  |  |

## Baseline scan results (vulnerable environment)

- Intentional flaws planted: 4
- tfsec findings: 15 (13 unique rules)
- Checkov failed checks: 27 (27 unique rules)
- Total findings: 42
- Findings per planted flaw: 10.5
- Blocking categories: TODO
- Confirmed false positives: 1 (tfsec aws-s3-enable-bucket-encryption - stale vs AWS SSE-S3 default, Jan 2023)
- Vacuous passes identified: 3 (CKV2_AWS_2, CKV_AWS_20, CKV_AWS_57)
