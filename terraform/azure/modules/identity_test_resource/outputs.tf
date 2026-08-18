# Every output the STEP 8C brief requires, plus the control case.
#
# Each is Azure's own value read back from the created resource — none
# is constructed by string interpolation in this file, so a scan can be
# compared against them without the fixture and the scanner sharing an
# assumption about how an id is spelled.

output "subscription_id" {
  description = "The subscription the privileged assignment is scoped to — what the scanner reports as account_id."
  value       = data.azurerm_subscription.current.subscription_id
}

output "subscription_scope" {
  description = "The canonical subscription scope id (/subscriptions/{guid}) the privileged assignment uses."
  value       = data.azurerm_subscription.current.id
}

output "principal_id" {
  description = "Entra object id of the user-assigned managed identity. This is the principal identity the scanner records — NOT the identity's resource id or its display name."
  value       = azurerm_user_assigned_identity.test.principal_id
}

output "principal_resource_id" {
  description = "ARM resource id of the managed identity itself. Distinct from principal_id: one is the directory object, the other is the Azure resource that owns it."
  value       = azurerm_user_assigned_identity.test.id
}

output "role_assignment_id" {
  description = "Full resource id of the PRIVILEGED (Owner at subscription scope) role assignment — the one the rule fires on."
  value       = azurerm_role_assignment.privileged.id
}

output "role_definition_id" {
  description = "Full resource id of the Owner role definition, as returned by Azure."
  value       = data.azurerm_role_definition.owner.id
}

output "scope" {
  description = "Scope of the privileged assignment. Equals subscription_scope; exposed separately because the brief asks for 'scope' as its own output and the two are only equal for this fixture."
  value       = azurerm_role_assignment.privileged.scope
}

output "benign_role_assignment_id" {
  description = "The control case: Reader at resource-group scope. The rule must NOT produce a finding for this one."
  value       = azurerm_role_assignment.benign.id
}

output "benign_role_definition_id" {
  description = "Full resource id of the Reader role definition."
  value       = data.azurerm_role_definition.reader.id
}
