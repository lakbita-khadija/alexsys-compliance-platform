# KMS test resources: one key with rotation enabled (compliant), one
# with rotation disabled (non-compliant). Matches blueprint §15's kms
# module table: "rotation activée" vs "rotation désactivée".
#
# Both are customer-managed symmetric keys with no real data encrypted
# under them — created purely to be scanned. `deletion_window_in_days`
# is set to the AWS minimum (7) so a `terraform destroy` doesn't leave
# a 30-day billing tail.

resource "aws_kms_key" "compliant" {
  description             = "ComplianceIQ test: rotation enabled"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "compliant" {
  name          = "alias/${var.name_prefix}-compliant"
  target_key_id = aws_kms_key.compliant.key_id
}

resource "aws_kms_key" "noncompliant" {
  description             = "ComplianceIQ test: INTENTIONALLY rotation disabled"
  deletion_window_in_days = 7
  enable_key_rotation     = false
}

resource "aws_kms_alias" "noncompliant" {
  name          = "alias/${var.name_prefix}-noncompliant"
  target_key_id = aws_kms_key.noncompliant.key_id
}

# ---------------------------------------------------------------------
# Third key: key policy grants access to any principal (Effect=Allow,
# Principal="*", no Condition) — the distinct exposure mechanism
# rules/aws/kms.yaml:kms-key-policy-allows-public-access exists to
# catch. Still includes the mandatory root-account statement AWS
# requires for a key policy to remain manageable at all.
# ---------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "policy_public" {
  statement {
    sid       = "EnableAccountRootManagement"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "IntentionallyPublicDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_kms_key" "policy_public" {
  description             = "ComplianceIQ test: INTENTIONALLY public key policy"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.policy_public.json
}

resource "aws_kms_alias" "policy_public" {
  name          = "alias/${var.name_prefix}-policy-public"
  target_key_id = aws_kms_key.policy_public.key_id
}
