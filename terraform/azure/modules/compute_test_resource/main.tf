# Virtual Machine test resources: one hardened (compliant) VM, one
# intentionally soft (non-compliant) VM. The Azure counterpart of
# ../../../aws/modules/ec2_test_resource, covering the facts collected
# by infrastructure/cloud/azure/resource_collectors/compute.py and
# evaluated by rules/azure/compute.yaml: public IP, managed identity,
# and the effective NSG reached through the VM's NIC and subnet.
#
# COST NOTE (blueprint Phase 3B brief, Part O): two `Standard_B1s`
# VMs, billed only while running, plus one Standard public IP.
# `terraform destroy` removes them; there is no reason to leave this
# module applied longer than a scan/demo session.
#
# CREDENTIALS: password authentication is disabled on both VMs and only
# a PUBLIC SSH key is ever passed in (see variables.tf). Terraform
# never generates or stores a private key or password here.

resource "azurerm_public_ip" "noncompliant" {
  name                = "${var.name_prefix}-pip-noncompliant"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ---------------------------------------------------------------------
# Compliant VM: no public IP, system-assigned managed identity, in the
# subnet governed by the restrictive NSG.
# ---------------------------------------------------------------------

resource "azurerm_network_interface" "compliant" {
  name                = "${var.name_prefix}-nic-compliant"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.compliant_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "compliant" {
  name                            = "${var.name_prefix}-vm-compliant"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = "Standard_B1s"
  admin_username                  = "complianceiq"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.compliant.id]

  admin_ssh_key {
    username   = "complianceiq"
    public_key = var.admin_ssh_public_key
  }

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

# ---------------------------------------------------------------------
# Non-compliant VM: public IP, no managed identity, in the subnet
# governed by the internet-open NSG — deliberately soft on every axis
# rules/azure/compute.yaml checks. Never used for anything but being
# scanned.
# ---------------------------------------------------------------------

resource "azurerm_network_interface" "noncompliant" {
  name                = "${var.name_prefix}-nic-noncompliant"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.noncompliant_subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.noncompliant.id
  }
}

resource "azurerm_linux_virtual_machine" "noncompliant" {
  name                            = "${var.name_prefix}-vm-noncompliant"
  location                        = var.location
  resource_group_name             = var.resource_group_name
  size                            = "Standard_B1s"
  admin_username                  = "complianceiq"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.noncompliant.id]

  admin_ssh_key {
    username   = "complianceiq"
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
