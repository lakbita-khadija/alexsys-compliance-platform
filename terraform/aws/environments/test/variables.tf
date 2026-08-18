variable "environment" {
  description = "Must be exactly \"test\" — see ../../variables.tf for why."
  type        = string
  default     = "test"

  validation {
    condition     = var.environment == "test"
    error_message = "environment must be exactly \"test\"."
  }
}

variable "aws_region" {
  description = "AWS region to provision the test environment in."
  type        = string
  default     = "us-east-1"
}

variable "tenant_id" {
  description = "ComplianceIQ tenant identifier tag (traceability only — see ../../variables.tf)."
  type        = string
  default     = "complianceiq-test-tenant"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name/tag."
  type        = string
  default     = "complianceiq-test"
}
