variable "environment" {
  description = "Must be exactly \"test\" — see ../../variables.tf for why this is hard-validated."
  type        = string
  default     = "test"
}

variable "location" {
  description = "Azure region to provision the test environment in."
  type        = string
  default     = "westeurope"
}

variable "tenant_id" {
  description = "ComplianceIQ tenant identifier (a tag only — NOT the Azure AD tenant id)."
  type        = string
  default     = "complianceiq-test-tenant"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name/tag created by this environment."
  type        = string
  default     = "complianceiq-test"
}

variable "storage_name_prefix" {
  description = "Prefix for storage account names (3-11 lowercase alphanumeric characters)."
  type        = string
  default     = "ciqtest"
}

variable "admin_ssh_public_key" {
  description = "An SSH PUBLIC key for the test VMs' admin user. No default — supply your own."
  type        = string
}
