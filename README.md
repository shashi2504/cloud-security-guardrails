# Cloud Security Guardrails

A CI security gate for AWS Terraform. Scanner findings are classified by an
explicit, version-controlled policy table, and only findings that represent
real exposure block a merge.

## Why this exists

Running tfsec and Checkov against four deliberately misconfigured AWS
resources produced **42 findings** — 10.5 alerts per actual flaw. A single
IAM policy with `Action: "*"` generated eleven separate findings across the
two tools.

A developer facing that volume on every pull request ignores all of it. The
scanners are not the hard part; deciding which findings justify stopping a
deployment is. That decision lives in
[`docs/triage.md`](docs/triage.md) and is enforced in CI.

Two findings from building it:

- **tfsec `aws-s3-enable-bucket-encryption` is a false positive.** AWS has
  applied SSE-S3 to all new buckets by default since January 2023. tfsec is
  in maintenance mode and has not caught up; Checkov's `CKV_AWS_19` passes
  the same bucket. Classified IGNORE with that reasoning recorded.
- **Three checks passed for the wrong reason.** `CKV2_AWS_2` passed because
  the unencrypted volume was not attached to an instance. `CKV_AWS_20` and
  `CKV_AWS_57` passed because the bucket is public via bucket *policy*
  rather than ACL. A wide-open bucket produced three PASSED results — which
  is why the security score is not passed-over-total.

## What is built

| Component | Status |
|---|---|
| IaC scanning (tfsec, Checkov) in GitHub Actions | Working |
| Triage table — 40 rules, 19 BLOCK / 16 WARN / 5 IGNORE | Working |
| Triage table executable as OPA data, drift-checked in CI | Working |
| Deliberately vulnerable environment as a detection regression test | Working |
| OPA policy unit tests (16) | Working |
| Terraform remote state, S3 backend with native locking | Working |
| Conditional S3 public-access policy (`PublicAccess=intentional`) | Written and tested, not yet in CI |
| Environment-aware severity gating | Written and tested, not yet in CI |

The two plan-based policies need `terraform plan` output, which requires AWS
credentials in Actions. That is deliberately unwired until a read-only IAM
role exists for it.

## What is not built

Prowler CSPM scanning, Grafana dashboards, SNS/Slack alerting, and Lambda
auto-remediation are described in [`docs/blueprint.md`](docs/blueprint.md)
but not implemented.

## Evidence

**Blocked merge** — a public S3 bucket added to `dev/`
([`docs/evidence/pr1-blocked.txt`](docs/evidence/pr1-blocked.txt)):

Blocking findings: 9
BLOCK [CKV2_AWS_6] Ensure that S3 bucket has a Public Access block
BLOCK [CKV_AWS_53] Ensure S3 bucket has block public ACLS enabled
BLOCK [CKV_AWS_54] Ensure S3 bucket has block public policy enabled
...


**Passing merge** — the same bucket with public access blocked
([`docs/evidence/pr3-passed.txt`](docs/evidence/pr3-passed.txt)):

Blocking findings: 0
OK: no blocking findings


The `vulnerable` environment runs on every pull request with an inverted
assertion: **zero blocking findings is a failure.** If a scanner upgrade or
an over-broad triage entry breaks detection, CI goes red. Most security
pipelines only prove they can pass; this one also proves it can still catch.

## Architecture

Pull request
↓
terraform fmt → fails on unformatted code
↓
tfsec + Checkov → scan; exit codes ignored, they do not gate
↓
normalize_findings.py → one schema across both tools
↓
OPA + triage.json → classify BLOCK / WARN / IGNORE / UNCLASSIFIED
↓
Gate → exit 1 if any BLOCK or UNCLASSIFIED


## Design decisions

**Ingress blocks, egress warns.** Unrestricted ingress is exposure.
Unrestricted egress is the AWS default on every security group; blocking it
would fail every pull request and the gate would be switched off within a
week. A control that gets disabled protects nothing. This would be revisited
for regulated data, where egress filtering is what stops exfiltration.

**Environment comes from CI, never from the code under evaluation.** The
severity policy reads the environment from the workflow matrix. If a pull
request could set `Environment = "dev"` in a production directory, it could
downgrade its own findings and the gate would be advisory.

**Unknown rule IDs fail closed.** A scanner version bump that adds new
checks surfaces them for classification rather than passing silently.

**The markdown table is the source of truth.** `scripts/extract_triage.py`
generates `policies/opa/triage.json` from `docs/triage.md`; CI runs it with
`--check` and fails if the two have drifted. Documentation that can silently
disagree with enforcement is worse than no documentation.

**Public buckets need an explicit opt-in tag.** A bucket tagged
`PublicAccess = intentional` passes the OPA policy; an untagged one is
denied. Neither scanner can express "unless", so in practice teams
blanket-suppress the rule and lose the signal entirely. This keeps the
detection and makes the exception auditable.

## Repository layout

terraform/environments/
dev/ clean baseline
vulnerable/ 4 intentional flaws — detection test fixture
policies/opa/ 3 Rego policies + tests + triage.json
scripts/ triage extraction, finding normalization
docs/triage.md the 40-rule classification with rationale
docs/evidence/ CI logs from blocked and passing runs


## Running it

Requires Terraform >= 1.10, tfsec, Checkov, OPA, and AWS credentials.

```bash
# Policy tests
opa test policies/opa -v

# Verify the triage table and its JSON are in sync
./scripts/extract_triage.py --check

# Deploy the test fixture (~$0.10/month, 1 GiB EBS volume)
cd terraform/environments/vulnerable && terraform init && terraform apply

# Scan and classify
cd ../../.. 
tfsec terraform/environments/vulnerable --format json \
  > scans/tfsec/output/vulnerable.json
checkov -d terraform/environments/vulnerable --framework terraform \
  --output json --output-file-path scans/checkov/output
SCAN_ENV=vulnerable ./scripts/normalize_findings.py > findings.json
opa eval --format pretty --data policies/opa/scanner_triage.rego \
  --data policies/opa/triage.json --input findings.json \
  'data.guardrails.triage.summary'

# Tear down
cd terraform/environments/vulnerable && terraform destroy
```

The `vulnerable` environment creates a world-readable S3 bucket. Never put
data in it, and destroy it when not in use.

## Versions

Terraform 1.16.0 · tfsec 1.28.14 · Checkov 3.3.15 · OPA 1.20.1 · region `ap-south-1`
