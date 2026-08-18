variable "name_prefix" {
  description = "Prefix applied to every resource name created by this module."
  type        = string
}

variable "subscription_id" {
  description = "The subscription whose Activity Log is exported."
  type        = string
}

variable "storage_account_id" {
  description = "Storage account the Activity Log is exported to (from storage_test_resource's audit-log account)."
  type        = string
}
