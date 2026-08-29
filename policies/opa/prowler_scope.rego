# Splits Prowler findings by whether a pull request could fix them.
#
# Account posture — root MFA, account-level settings, IAM user
# configuration — is real and often severe, but no commit resolves it.
# Gating merges on it means every PR fails until someone visits the
# console, which teaches people to bypass the gate. These findings belong
# on a dashboard and in a ticket.
#
# Resource findings trace to infrastructure code and are fixable in a PR.
# Those gate.

package guardrails.prowler.scope

import rego.v1

# Checks that describe standing account configuration, not deployed resources.
account_posture_checks := {
	"iam_root_hardware_mfa_enabled",
	"iam_root_mfa_enabled",
	"iam_avoid_root_usage",
	"iam_user_hardware_mfa_enabled",
	"iam_user_mfa_enabled",
	"iam_user_with_temporary_credentials",
	"iam_user_administrator_access_policy",
	"iam_aws_attached_policy_no_administrative_privileges",
	"iam_customer_unattached_policy_no_administrative_privileges",
	"iam_support_role_created",
	"iam_securityaudit_role_created",
	"iam_check_saml_providers_sts",
	"s3_account_level_public_access_blocks",
	"ec2_ebs_default_encryption",
	"ec2_networkacl_allow_ingress_any_port",
	"ec2_networkacl_allow_ingress_tcp_port_22",
	"ec2_networkacl_allow_ingress_tcp_port_3389",
}

is_account_posture(rule_id) if rule_id in account_posture_checks

is_account_posture(rule_id) if startswith(rule_id, "iam_password_policy_")
