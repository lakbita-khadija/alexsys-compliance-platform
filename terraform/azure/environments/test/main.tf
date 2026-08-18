# The actual deployable root for the ComplianceIQ Azure test
# environment. `terraform/azure/` (one level up) is a reusable module
# composing the five test-resource modules; this file is what you
# actually `terraform init`/`apply` from.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # No backend block: this test environment intentionally uses local
  # state (see ../../README.md, "State"). For anything longer-lived
  # than a demo, configure a remote backend here — never commit
  # terraform.tfstate either way (see the .gitignore at the repository
  # root).
}

module "compliance_test_environment" {
  source = "../../"

  environment          = var.environment
  location             = var.location
  tenant_id            = var.tenant_id
  name_prefix          = var.name_prefix
  storage_name_prefix  = var.storage_name_prefix
  admin_ssh_public_key = var.admin_ssh_public_key
}

output "subscription_id" {
  value = module.compliance_test_environment.subscription_id
}

output "resource_group_name" {
  value = module.compliance_test_environment.resource_group_name
}

output "compliant_storage_account_id" {
  value = module.compliance_test_environment.compliant_storage_account_id
}

output "noncompliant_storage_account_id" {
  value = module.compliance_test_environment.noncompliant_storage_account_id
}

output "audit_logs_storage_account_id" {
  value = module.compliance_test_environment.audit_logs_storage_account_id
}

output "compliant_nsg_id" {
  value = module.compliance_test_environment.compliant_nsg_id
}

output "noncompliant_nsg_id" {
  value = module.compliance_test_environment.noncompliant_nsg_id
}

output "compliant_vm_id" {
  value = module.compliance_test_environment.compliant_vm_id
}

output "noncompliant_vm_id" {
  value = module.compliance_test_environment.noncompliant_vm_id
}

output "compliant_key_vault_id" {
  value = module.compliance_test_environment.compliant_key_vault_id
}

output "noncompliant_key_vault_id" {
  value = module.compliance_test_environment.noncompliant_key_vault_id
}

output "activity_log_setting_id" {
  value = module.compliance_test_environment.activity_log_setting_id
}
