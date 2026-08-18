variable "name_prefix" {
  description = "Prefix applied to every resource name created by this module."
  type        = string
}

variable "compliant_security_group_id" {
  description = "The restrictive security group (from network_test_resource) to attach to the compliant instance."
  type        = string
}

variable "noncompliant_security_group_id" {
  description = "The security group with SSH open to 0.0.0.0/0 (from network_test_resource) to attach to the non-compliant instance — also exercises the ec2-instance-attached-to-open-security-group relationship rule."
  type        = string
}
