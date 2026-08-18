variable "name_prefix" {
  description = "Prefix applied to every resource name created by this module."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the network resources in."
  type        = string
}
