# CloudTrail test resource: one compliant trail — multi-region, log
# file validation enabled, actively logging. Matches blueprint §15's
# cloudtrail module table's compliant state ("multi-région, validation
# activée").
#
# Only one trail is created (the Phase 3 brief's §16 instruction for
# CloudTrail asks only for "CloudTrail enabled", not an explicit
# compliant/non-compliant pair like S3 and security groups get) — a
# second, deliberately single-region trail was considered but skipped
# to avoid the cost/complexity of running two trails in one AWS
# account; the "non-compliant" branches of the CloudTrail rules
# (rules/aws/cloudtrail.yaml) are already proven at the unit-test level
# (tests/unit/infrastructure/test_aws_cloudtrail_collector.py).

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "${var.name_prefix}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "trail_logs" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioned so the trail passes rules/aws/cloudtrail.yaml's
# cloudtrail-logs-to-non-versioned-bucket relationship rule — a real
# audit log bucket should be versioned regardless, so this is simply
# the compliant configuration, not a rule-specific special case.
resource "aws_s3_bucket_versioning" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "trail_logs" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = data.aws_iam_policy_document.trail_logs.json
}

resource "aws_cloudtrail" "compliant" {
  depends_on = [aws_s3_bucket_policy.trail_logs]

  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}
