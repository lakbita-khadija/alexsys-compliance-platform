# Storage account test resources: one compliant, one intentionally
# non-compliant, plus a private audit-log destination used by the
# monitor module. The Azure counterpart of
# ../../../aws/modules/s3_test_resource.
#
# No real data is ever stored in any of these accounts — they are
# created empty and stay empty; only their configuration is under test.

# ---------------------------------------------------------------------
# Compliant: HTTPS enforced, no anonymous blob access, TLS 1.2,
# default-deny firewall, blob soft delete on.
# ---------------------------------------------------------------------

resource "azurerm_storage_account" "compliant" {
  name                = "${var.storage_name_prefix}ok${var.unique_suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

# ---------------------------------------------------------------------
# Non-compliant: anonymous blob access allowed, plaintext HTTP
# permitted, TLS 1.0 floor, default-allow firewall, no soft delete.
#
# Deliberately insecure — this is the entire point of the module. It is
# created empty and stays empty; nothing is ever written to it.
# ---------------------------------------------------------------------

resource "azurerm_storage_account" "noncompliant" {
  name                = "${var.storage_name_prefix}bad${var.unique_suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_traffic_only_enabled      = false
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"

  network_rules {
    default_action = "Allow"
  }
}

# ---------------------------------------------------------------------
# Audit log destination for the monitor module's diagnostic setting.
# Kept compliant (private, soft-delete on) so the Activity Log
# relationship rules PASS against a correctly-configured environment —
# their failing branches are proven at the conformance-suite level
# (tests/conformance/scenarios/azure_network_compute.yaml).
# ---------------------------------------------------------------------

resource "azurerm_storage_account" "audit_logs" {
  name                = "${var.storage_name_prefix}log${var.unique_suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}
