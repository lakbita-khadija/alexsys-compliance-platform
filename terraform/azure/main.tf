data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  lower   = true
  upper   = false
  numeric = true
  special = false
}

# One resource group holds the whole environment, so `terraform
# destroy` (or, in the worst case, deleting the group by hand) reliably
# removes every billable resource this module creates.
resource "azurerm_resource_group" "test" {
  name     = "${var.name_prefix}-rg"
  location = var.location
}

module "storage_test_resource" {
  source              = "./modules/storage_test_resource"
  storage_name_prefix = var.storage_name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name
  unique_suffix       = random_string.suffix.result
}

module "network_test_resource" {
  source              = "./modules/network_test_resource"
  name_prefix         = var.name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name
}

module "compute_test_resource" {
  source                 = "./modules/compute_test_resource"
  name_prefix            = var.name_prefix
  location               = var.location
  resource_group_name    = azurerm_resource_group.test.name
  compliant_subnet_id    = module.network_test_resource.compliant_subnet_id
  noncompliant_subnet_id = module.network_test_resource.noncompliant_subnet_id
  admin_ssh_public_key   = var.admin_ssh_public_key
}

module "keyvault_test_resource" {
  source              = "./modules/keyvault_test_resource"
  name_prefix         = var.name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name
  azure_tenant_id     = data.azurerm_client_config.current.tenant_id
  unique_suffix       = random_string.suffix.result
}

module "monitor_test_resource" {
  source             = "./modules/monitor_test_resource"
  name_prefix        = var.name_prefix
  subscription_id    = data.azurerm_client_config.current.subscription_id
  storage_account_id = module.storage_test_resource.audit_logs_storage_account_id
}

# --- STEP 8C — Azure identity / RBAC fixture.
#
# OPT-IN, and that is a safety decision rather than a stylistic one.
# This module grants **Owner on the whole subscription** to a managed
# identity. Every other module here creates resources scoped to the
# test resource group; this one reaches outside it by design, because
# subscription scope is exactly what the rule under test detects.
#
# Defaulting it on would mean someone running `terraform apply` to
# refresh the storage fixtures silently acquires a permanent
# subscription-wide Owner assignment. So it is off unless asked for.
module "identity_test_resource" {
  count               = var.enable_identity_rbac_fixture ? 1 : 0
  source              = "./modules/identity_test_resource"
  name_prefix         = var.name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name
  resource_group_id   = azurerm_resource_group.test.id
}
