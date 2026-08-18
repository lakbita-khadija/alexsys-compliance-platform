output "compliant_key_vault_id" {
  value = azurerm_key_vault.compliant.id
}

output "noncompliant_key_vault_id" {
  value = azurerm_key_vault.noncompliant.id
}
