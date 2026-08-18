variable "name_prefix" {
  description = "Prefix for resource names (see the root module's variable of the same name)."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the managed identity in."
  type        = string
}

variable "resource_group_id" {
  description = "Full resource id of the resource group, used as the scope of the benign (control-case) role assignment."
  type        = string
}
