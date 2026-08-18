# S3 test resources: one compliant bucket, one intentionally
# non-compliant bucket. Compliant/non-compliant shape matches blueprint
# §15's S3 module table exactly: "bucket privé, chiffré, versionné" vs
# "bucket public, non chiffré".
#
# No real data is ever stored in either bucket — both are created and
# left empty; only their configuration is under test.

data "aws_caller_identity" "current" {}

locals {
  suffix = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------
# Compliant bucket: private, encrypted, versioned, logged
# ---------------------------------------------------------------------

resource "aws_s3_bucket" "compliant" {
  bucket = "${var.name_prefix}-compliant-${local.suffix}"
}

resource "aws_s3_bucket_ownership_controls" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket                  = aws_s3_bucket.compliant.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "compliant" {
  depends_on = [
    aws_s3_bucket_ownership_controls.compliant,
    aws_s3_bucket_public_access_block.compliant,
  ]
  bucket = aws_s3_bucket.compliant.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.name_prefix}-access-logs-${local.suffix}"
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "access_logs" {
  depends_on = [aws_s3_bucket_ownership_controls.access_logs]
  bucket     = aws_s3_bucket.access_logs.id
  acl        = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "compliant" {
  bucket        = aws_s3_bucket.compliant.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "log/"
}

# ---------------------------------------------------------------------
# Non-compliant bucket: public, unencrypted, unversioned, unlogged
#
# Deliberately insecure — this is the entire point of the module. Never
# store real data here; it is created empty and stays empty.
# ---------------------------------------------------------------------

resource "aws_s3_bucket" "noncompliant" {
  bucket = "${var.name_prefix}-noncompliant-${local.suffix}"
}

resource "aws_s3_bucket_ownership_controls" "noncompliant" {
  bucket = aws_s3_bucket.noncompliant.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "noncompliant" {
  bucket                  = aws_s3_bucket.noncompliant.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "noncompliant" {
  depends_on = [
    aws_s3_bucket_ownership_controls.noncompliant,
    aws_s3_bucket_public_access_block.noncompliant,
  ]
  bucket = aws_s3_bucket.noncompliant.id
  acl    = "public-read"
}

# ---------------------------------------------------------------------
# Third bucket: exposed through its bucket POLICY rather than its ACL
# — the distinct exposure mechanism
# rules/aws/s3.yaml:s3-bucket-policy-allows-public-access exists to
# catch, which the ACL-based `noncompliant` bucket above does not
# exercise (its policy is unset; only its ACL is public).
# ---------------------------------------------------------------------

resource "aws_s3_bucket" "policy_public" {
  bucket = "${var.name_prefix}-policy-public-${local.suffix}"
}

resource "aws_s3_bucket_public_access_block" "policy_public" {
  bucket                  = aws_s3_bucket.policy_public.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

data "aws_iam_policy_document" "policy_public" {
  statement {
    sid       = "IntentionallyPublicRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.policy_public.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "policy_public" {
  depends_on = [aws_s3_bucket_public_access_block.policy_public]
  bucket     = aws_s3_bucket.policy_public.id
  policy     = data.aws_iam_policy_document.policy_public.json
}
