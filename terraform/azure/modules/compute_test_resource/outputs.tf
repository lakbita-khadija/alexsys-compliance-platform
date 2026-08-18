output "compliant_vm_id" {
  value = azurerm_linux_virtual_machine.compliant.id
}

output "noncompliant_vm_id" {
  value = azurerm_linux_virtual_machine.noncompliant.id
}
