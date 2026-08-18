# STEP 8C — Azure identity / RBAC fixture.
#
# The minimum that exercises the full chain the collectors model:
#
#   principal -> role assignment -> role definition
#                      |
#                      +-> scope
#
# A **user-assigned managed identity** is the principal, chosen over a
# user, a group or an app registration for one reason: it is created
# deterministically by Terraform with no Entra admin consent, no manual
# portal step, and no credential to store or leak. An `azuread_user`
# needs a directory licence and a password; an app registration needs a
# client secret this repository has a standing rule against creating.
#
# Two assignments, deliberately paired:
#
#   * `privileged` — Owner at SUBSCRIPTION scope. Fires the rule.
#   * `benign`     — Reader at RESOURCE GROUP scope. Must NOT fire, and
#                    proves the rule is testing both halves of its AND
#                    rather than passing for the wrong reason.
#
# COST: a user-assigned managed identity and role assignments are free.
# This module creates no billable resource. The real cost is BLAST
# RADIUS, not money — see README.md.

terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

data "azurerm_subscription" "current" {}

# Built-in role definitions, read rather than created. Their GUIDs are
# stable across every Azure tenant, but they are looked up by name so
# the fixture does not hardcode an id — and so `role_definition_id`
# below is Azure's own value, not one this file asserts.
data "azurerm_role_definition" "owner" {
  name = "Owner"
}

data "azurerm_role_definition" "reader" {
  name = "Reader"
}

resource "azurerm_user_assigned_identity" "test" {
  name                = "${var.name_prefix}-scanner-test-identity"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    purpose = "complianceiq-step-8c-rbac-fixture"
    # Deliberately findable: this identity holds Owner on the
    # subscription, and anyone auditing the tenant should be able to
    # see what it is for without reading Terraform.
    warning = "intentionally-privileged-test-fixture-destroy-after-use"
  }
}

# --- The finding this fixture exists to produce.
#
# Owner carries `actions = ["*"]`, so `grants_all_actions` is true, and
# the scope is the whole subscription. Both halves of
# `azure-privileged-role-assigned-at-subscription-scope`.
resource "azurerm_role_assignment" "privileged" {
  scope              = data.azurerm_subscription.current.id
  role_definition_id = data.azurerm_role_definition.owner.id
  principal_id       = azurerm_user_assigned_identity.test.principal_id
}

# --- The control case.
#
# Reader has no wildcard action AND is scoped to one resource group.
# The rule must stay silent on it. Without this pair, a rule that fired
# on every assignment would look correct.
resource "azurerm_role_assignment" "benign" {
  scope              = var.resource_group_id
  role_definition_id = data.azurerm_role_definition.reader.id
  principal_id       = azurerm_user_assigned_identity.test.principal_id
}
