variable "environment" {
  description = <<-EOT
    Deployment environment. This module provisions a REAL, BILLABLE AWS
    test environment for ComplianceIQ scanning demonstrations,
    including deliberately insecure resources (an open security group,
    a public S3 bucket, an MFA-less IAM user, an unrotated KMS key).
    It must never be pointed at production — see README.md.
  EOT
  type        = string

  validation {
    condition     = var.environment == "test"
    error_message = "environment must be exactly \"test\". This module refuses any other value to prevent an accidental production deployment of intentionally insecure resources."
  }
}

variable "aws_region" {
  description = "AWS region to provision the test environment in."
  type        = string
  default     = "us-east-1"
}

variable "tenant_id" {
  description = <<-EOT
    ComplianceIQ tenant identifier this environment is scanned as.
    Purely a resource tag here for traceability — Terraform never
    determines tenant identity for the scanner. The actual tenant_id
    used by ScanCloudAccount is supplied by its caller
    (application/scanning/scan_cloud_account.py), independently of this
    tag (blueprint Phase 3 brief §8: the AWS account/environment must
    never itself be treated as the tenant).
  EOT
  type        = string
  default     = "complianceiq-test-tenant"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name/tag created by this environment, so ownership is obvious and names don't collide with unrelated resources."
  type        = string
  default     = "complianceiq-test"
}
