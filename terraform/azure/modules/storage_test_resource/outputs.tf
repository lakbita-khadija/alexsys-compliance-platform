output "compliant_storage_account_id" {
  value = azurerm_storage_account.compliant.id
}

output "noncompliant_storage_account_id" {
  value = azurerm_storage_account.noncompliant.id
}

output "audit_logs_storage_account_id" {
  value = azurerm_storage_account.audit_logs.id
}
