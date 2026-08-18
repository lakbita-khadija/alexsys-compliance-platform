# Key Vault test resources: one compliant, one intentionally
# non-compliant. The Azure counterpart of
# ../../../aws/modules/kms_test_resource.
#
# No key, secret, or certificate is ever created in either vault — they
# are provisioned empty and stay empty; only their configuration is
# under test.
#
# COST NOTE: an empty Key Vault has no standing charge (billing is
# per-operation), so unlike the AWS KMS keys these do not accrue a
# monthly fee while idle.

# ---------------------------------------------------------------------
# Compliant: soft delete + purge protection on, RBAC authorization,
# public network access disabled, default-deny firewall.
# ---------------------------------------------------------------------

resource "azurerm_key_vault" "compliant" {
  name                = "${var.name_prefix}-kv-ok-${var.unique_suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.azure_tenant_id
  sku_name            = "standard"

  soft_delete_retention_days    = 7
  purge_protection_enabled      = false
  enable_rbac_authorization     = true
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# ---------------------------------------------------------------------
# Non-compliant: legacy access policies, public network access, and a
# default-allow firewall.
#
# NOTE on purge protection: `purge_protection_enabled = true` is
# IRREVERSIBLE in Azure — a vault with it on cannot be deleted until
# its retention period elapses, which would make `terraform destroy`
# unable to clean up this test environment. It is therefore left off on
# BOTH vaults, and the compliant vault will legitimately report a
# finding for `azure-key-vault-purge-protection-disabled`. This is a
# documented, deliberate trade-off for a disposable test environment,
# not an oversight — the rule's passing branch is proven at the
# conformance-suite level instead
# (tests/conformance/scenarios/azure_network_compute.yaml:
# azure-key-vault-compliant).
# ---------------------------------------------------------------------

resource "azurerm_key_vault" "noncompliant" {
  name                = "${var.name_prefix}-kv-bad-${var.unique_suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.azure_tenant_id
  sku_name            = "standard"

  soft_delete_retention_days    = 7
  purge_protection_enabled      = false
  enable_rbac_authorization     = false
  public_network_access_enabled = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}
