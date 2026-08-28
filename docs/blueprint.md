# Original Project Blueprint

The original scope for this project, kept for reference. Sections marked
NOT BUILT are described here but not implemented — see the README for what
actually exists.

## Vision

A cloud security platform that enforces secure AWS deployments, prevents
insecure Infrastructure as Code, continuously monitors security posture,
generates compliance reports, and automatically remediates critical risks.

## Modules

**Module 1 — Secure landing zone.** VPC with public/private subnets, NAT
gateway, IAM roles, security groups, CloudTrail, CloudWatch, KMS, S3 logging
bucket. NOT BUILT.

**Module 2 — IaC security guardrails.** Terraform, Checkov, tfsec, and Open
Policy Agent gating deployments in CI/CD. BUILT — this is the current scope.

**Module 3 — CSPM engine.** Prowler running CIS benchmark checks against the
live account: IAM permissions, S3 exposure, open ports, CloudTrail state,
KMS usage, MFA. NOT BUILT.

**Module 4 — Monitoring and logging.** CloudWatch, CloudTrail, and a Grafana
dashboard showing security score, public resource count, IAM risks, failed
policies. NOT BUILT.

**Module 5 — Alerting.** SNS topics, Slack webhooks, email alerts on
critical findings. NOT BUILT.

**Module 6 — Auto remediation.** Lambda functions triggered by EventBridge
to remove public S3 access, restrict open security groups, encrypt volumes,
re-enable disabled logging. NOT BUILT.

## Deviations from the original plan

**A deliberately vulnerable environment was added.** The original plan built
a secure landing zone and then scanned it, which proves nothing — the
scanners pass because the infrastructure was built correctly. A broken
environment gives the detection layer something real to find, and its
findings are asserted in CI as a regression test.

**Build order was inverted.** The original Phase 1 was the landing zone.
Building the vulnerable fixture and the scanning layer first meant every
tool added could be validated immediately rather than at the end.

**Auto-remediation is scoped down.** The original "unencrypted EBS →
snapshot and encrypt" flow requires detaching the volume and stopping the
instance, which is an outage rather than a remediation. Any remediation
built here will default to dry-run, be restricted by resource tag, and
require an approval gate for destructive actions.

**The security score needs definition.** The original specified a score
without saying how it is computed. Passed-over-total is misleading: three
checks passed on a world-readable bucket during baseline scanning because
they tested conditions that did not apply. Any score here must be
severity-weighted and account for vacuous passes.

**NAT gateway dropped.** Roughly $32/month and not free-tier eligible. Not
required for anything in the current scope.
