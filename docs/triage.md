# Finding Triage Policy

Every rule from tfsec and Checkov is classified BLOCK, WARN, or IGNORE.
Each IGNORE requires a written justification.

| Tool | Rule ID | Description | Class | Rationale |
|------|---------|-------------|-------|-----------|
| tfsec | | | | |

## Baseline scan results (vulnerable environment)

- Intentional flaws planted: 4
- tfsec findings: 15 (13 unique rules)
- Checkov failed checks: 27 (27 unique rules)
- Total findings: 42
- Findings per planted flaw: 10.5
- Blocking categories: 4 (17 rule IDs)
- Confirmed false positives: 1 (tfsec aws-s3-enable-bucket-encryption — stale vs AWS SSE-S3 default, Jan 2023)
- Vacuous passes identified: 3 (CKV2_AWS_2, CKV_AWS_20, CKV_AWS_57)
