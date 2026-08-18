output "compliant_nsg_id" {
  value = azurerm_network_security_group.compliant.id
}

output "noncompliant_nsg_id" {
  value = azurerm_network_security_group.noncompliant.id
}

output "compliant_subnet_id" {
  value = azurerm_subnet.compliant.id
}

output "noncompliant_subnet_id" {
  value = azurerm_subnet.noncompliant.id
}
