variable "name_prefix" {
  description = "Prefix applied to every resource name created by this module."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the key vaults in."
  type        = string
}

variable "azure_tenant_id" {
  description = "The Azure AD tenant id the vaults belong to (NOT ComplianceIQ's own tenant identifier)."
  type        = string
}

variable "unique_suffix" {
  description = "Short suffix making the globally-unique key vault names collision-resistant."
  type        = string
}
