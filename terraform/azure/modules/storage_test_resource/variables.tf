variable "storage_name_prefix" {
  description = "Prefix for storage account names (see the root module's variable of the same name for Azure's naming constraints)."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the storage accounts in."
  type        = string
}

variable "unique_suffix" {
  description = "Short suffix making the globally-unique storage account names collision-resistant."
  type        = string
}
