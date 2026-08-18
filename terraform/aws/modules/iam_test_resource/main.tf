# IAM test resource: one intentionally non-compliant IAM user (no MFA
# device). Matches blueprint §15's iam_user module table: "MFA actif"
# (compliant) vs "MFA absent" (non-compliant).
#
# No compliant counterpart is provisioned here: registering a virtual
# MFA device requires an interactive TOTP/QR-code enrollment step that
# cannot be automated by Terraform alone (there is no
# `aws_iam_virtual_mfa_device` seed-and-activate flow without a human
# authenticator app). This is a documented limitation, not a cut
# corner — see ../../README.md.
#
# Least privilege: this user has NO attached policies (zero
# permissions) and Terraform never creates an access key for it — long-
# lived credentials are never generated or stored in state.

resource "aws_iam_user" "noncompliant_no_mfa" {
  name = "${var.name_prefix}-user-no-mfa"
  path = "/complianceiq-test/"
}

# ---------------------------------------------------------------------
# Second non-compliant user: has the AWS-managed AdministratorAccess
# policy attached directly (rules/aws/iam.yaml:
# iam-user-full-admin-policy-attached). Also has no MFA, so it
# additionally exercises iam-user-mfa-disabled and
# iam-user-access-key-without-mfa (no access key is created here,
# though — see the "no long-lived credentials" note above).
# ---------------------------------------------------------------------

resource "aws_iam_user" "noncompliant_full_admin" {
  name = "${var.name_prefix}-user-full-admin"
  path = "/complianceiq-test/"
}

resource "aws_iam_user_policy_attachment" "noncompliant_full_admin" {
  user       = aws_iam_user.noncompliant_full_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------------------
# Account-wide password policy: one resource, account-scoped, so it
# can only ever represent one state at a time — set to the compliant
# configuration (rules/aws/iam.yaml's iam-account-password-policy-*
# rules should all PASS against this environment). Their non-compliant
# branches are proven at the unit-test level
# (tests/unit/infrastructure/test_aws_iam_collector.py), the same
# convention already used for CloudTrail's single-trail limitation
# (see ../cloudtrail_test_resource/main.tf).
# ---------------------------------------------------------------------

resource "aws_iam_account_password_policy" "compliant" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}
