# Network Security Group test resources: one compliant (restrictive),
# one intentionally insecure. The Azure counterpart of
# ../../../aws/modules/network_test_resource.
#
# Also provisions the minimal virtual network and subnets the compute
# module's VMs need — Azure has no "default VPC" equivalent, so unlike
# the AWS module this one must create its own network. Kept as small as
# possible: one VNet, two subnets, no gateways, no NAT, no load
# balancers (blueprint Phase 3 brief, Part O: avoid expensive
# infrastructure).

resource "azurerm_virtual_network" "test" {
  name                = "${var.name_prefix}-vnet"
  address_space       = ["10.42.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

# ---------------------------------------------------------------------
# Compliant NSG: HTTPS only, from inside the VNet — never Internet.
# ---------------------------------------------------------------------

resource "azurerm_network_security_group" "compliant" {
  name                = "${var.name_prefix}-nsg-compliant"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowInternalHttps"
    description                = "HTTPS from within the virtual network only"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }
}

# ---------------------------------------------------------------------
# Non-compliant NSG: SSH and RDP open to the entire internet.
#
# This is the deliberate misconfiguration the scanner is meant to catch
# (rules/azure/network.yaml: azure-nsg-ssh-open-to-internet,
# azure-nsg-rdp-open-to-internet). This environment is explicitly a
# ComplianceIQ security-testing environment (see ../../README.md);
# these rules must never be replicated in a real network.
# ---------------------------------------------------------------------

resource "azurerm_network_security_group" "noncompliant" {
  name                = "${var.name_prefix}-nsg-noncompliant"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "IntentionallyInsecureSsh"
    description                = "INTENTIONALLY insecure: SSH from anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "IntentionallyInsecureRdp"
    description                = "INTENTIONALLY insecure: RDP from anywhere"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # A Deny rule from a wildcard source, to prove the normalizer
  # correctly ignores Deny rules when computing
  # `has_unrestricted_ingress` (see
  # infrastructure/cloud/azure/normalizers/network.py).
  security_rule {
    name                       = "DenyEverythingElse"
    description                = "Deny rule — must NOT count as unrestricted ingress"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ---------------------------------------------------------------------
# Subnets, one per VM, each associated with one of the NSGs above.
# ---------------------------------------------------------------------

resource "azurerm_subnet" "compliant" {
  name                 = "${var.name_prefix}-subnet-compliant"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_subnet" "noncompliant" {
  name                 = "${var.name_prefix}-subnet-noncompliant"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.42.2.0/24"]
}

resource "azurerm_subnet_network_security_group_association" "compliant" {
  subnet_id                 = azurerm_subnet.compliant.id
  network_security_group_id = azurerm_network_security_group.compliant.id
}

resource "azurerm_subnet_network_security_group_association" "noncompliant" {
  subnet_id                 = azurerm_subnet.noncompliant.id
  network_security_group_id = azurerm_network_security_group.noncompliant.id
}
