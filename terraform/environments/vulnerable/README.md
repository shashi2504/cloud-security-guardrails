# Vulnerable Environment

Deliberately misconfigured AWS resources used to validate that the
scanning and remediation pipeline actually detects and fixes issues.

**Never store real data here. Destroy when not actively testing.**

## Intentional flaws and expected detections

| # | Flaw | Resource | Expected detection |
|---|------|----------|--------------------|
| 1 | Public read bucket policy | aws_s3_bucket_policy.public_read | tfsec, Checkov, Prowler, custom OPA |
| 1a | Public access block disabled | aws_s3_bucket_public_access_block | Checkov, Prowler |
| 1b | No versioning | aws_s3_bucket.public_data | tfsec, Checkov |
| 1c | No access logging | aws_s3_bucket.public_data | tfsec, Checkov |
| 2 | SSH (22) open to 0.0.0.0/0 | aws_security_group.wide_open | tfsec, Checkov, Prowler, custom OPA |
| 2a | RDP (3389) open to 0.0.0.0/0 | aws_security_group.wide_open | tfsec, Checkov, Prowler |
| 3 | Unencrypted EBS volume | aws_ebs_volume.unencrypted | tfsec, Checkov, Prowler |
| 4 | IAM policy with Action:* Resource:* | aws_iam_policy.overly_permissive | Checkov, Prowler, custom OPA |

## Cost
~$0.10/month (1 GiB gp3 volume). All other resources are free.

## Teardown
    terraform destroy
