variable "environment" {
  description = <<-EOT
    Deployment environment. This module provisions a REAL, BILLABLE Azure
    test environment for ComplianceIQ scanning demonstrations,
    including deliberately insecure resources (an NSG open to the
    internet, a storage account allowing anonymous blob access, an
    unprotected Key Vault). It must never be pointed at production —
    see README.md.
  EOT
  type        = string

  validation {
    condition     = var.environment == "test"
    error_message = "environment must be exactly \"test\". This module refuses any other value to prevent an accidental production deployment of intentionally insecure resources."
  }
}

variable "location" {
  description = "Azure region to provision the test environment in."
  type        = string
  default     = "westeurope"
}

variable "tenant_id" {
  description = <<-EOT
    ComplianceIQ tenant identifier this environment is scanned as.
    Purely a resource tag here for traceability — Terraform never
    determines tenant identity for the scanner, and this is NOT the
    Azure AD tenant id. The actual tenant_id used by ScanCloudAccount
    is supplied by its caller
    (application/scanning/scan_cloud_account.py), independently of this
    tag (blueprint Phase 3 brief §8: the cloud subscription must never
    itself be treated as the tenant).
  EOT
  type        = string
  default     = "complianceiq-test-tenant"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name/tag created by this environment, so ownership is obvious and names don't collide with unrelated resources."
  type        = string
  default     = "complianceiq-test"
}

variable "storage_name_prefix" {
  description = <<-EOT
    Prefix for storage account names specifically. Azure storage
    account names are globally unique, lowercase-alphanumeric only, and
    capped at 24 characters — far stricter than every other resource
    name — so they cannot reuse `name_prefix` directly.
  EOT
  type        = string
  default     = "ciqtest"

  validation {
    condition     = can(regex("^[a-z0-9]{3,11}$", var.storage_name_prefix))
    error_message = "storage_name_prefix must be 3-11 lowercase alphanumeric characters (Azure storage account naming rules leave room for a suffix)."
  }
}

variable "admin_ssh_public_key" {
  description = <<-EOT
    An SSH PUBLIC key for the test VMs' admin user. Azure requires
    either a password or an SSH key on every Linux VM; a public key is
    the safe choice. No private key or password is ever generated,
    stored, or written to Terraform state by this configuration.
    Supply your own public key (e.g. the contents of
    ~/.ssh/id_ed25519.pub) — there is deliberately no default.
  EOT
  type        = string
}

variable "enable_identity_rbac_fixture" {
  description = <<-EOT
    Create the STEP 8C RBAC fixture (user-assigned managed identity +
    Owner at SUBSCRIPTION scope + Reader at resource-group scope).

    Defaults to false because it grants subscription-wide Owner, which
    is outside the blast radius every other module in this environment
    keeps. Requires Microsoft.Authorization/roleAssignments/write on
    the subscription — typically Owner or User Access Administrator.

    See terraform/azure/modules/identity_test_resource/README.md.
  EOT
  type        = bool
  default     = false
}
