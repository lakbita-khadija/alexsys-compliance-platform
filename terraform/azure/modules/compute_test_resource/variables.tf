variable "name_prefix" {
  description = "Prefix applied to every resource name created by this module."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the virtual machines in."
  type        = string
}

variable "compliant_subnet_id" {
  description = "Subnet associated with the restrictive NSG (from network_test_resource)."
  type        = string
}

variable "noncompliant_subnet_id" {
  description = "Subnet associated with the internet-open NSG (from network_test_resource) — also exercises the azure-vm-attached-to-open-network-security-group relationship rule."
  type        = string
}

variable "admin_ssh_public_key" {
  description = <<-EOT
    An SSH PUBLIC key for the VMs' admin user. Azure requires either a
    password or an SSH key on every Linux VM; a public key is the safe
    choice, and no private key or password is ever generated, stored,
    or written to Terraform state by this module. Supply your own
    public key — there is deliberately no default.
  EOT
  type        = string
}
