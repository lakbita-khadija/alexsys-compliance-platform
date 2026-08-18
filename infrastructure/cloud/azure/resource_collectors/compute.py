"""Azure Virtual Machine collection.

The one genuinely more involved collector on the Azure side: a VM's
effective network security group and public IP are not properties of
the VM at all. Both hang off its network interfaces:

    VM -> networkProfile.networkInterfaces[] -> NIC
    NIC -> networkSecurityGroup            (direct NSG association)
    NIC -> ipConfigurations[].subnet       -> subnet NSG
    NIC -> ipConfigurations[].publicIPAddress -> public IP

Resolving that chain is deliberately done HERE rather than in the
normalizer, mirroring how the EC2 collector extracts security group ids
before handing plain values to ``normalize_ec2_instance``. NIC lookups
that fail are skipped rather than aborting the whole VM — a partially
resolved VM is still worth reporting, and the resulting absent
attribute correctly evaluates to INDETERMINATE rather than a false PASS.
"""

from __future__ import annotations

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.compute import normalize_virtual_machine
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector


class VirtualMachineCollector(AzureResourceCollector):
    """Collects every virtual machine in the subscription."""

    resource_type = "virtual machines"

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context="collecting virtual machines")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        machines = list(self._clients.compute.virtual_machines.list_all())
        return tuple(self._normalize(machine, collected_at) for machine in machines)

    def _normalize(self, machine, collected_at) -> NormalizedResource:
        nsg_ids, public_ip = self._resolve_network(machine)
        identity = getattr(machine, "identity", None)
        identity_type = _enum_value(getattr(identity, "type", None)) if identity is not None else None

        return normalize_virtual_machine(
            resource_id=machine.id,
            name=getattr(machine, "name", "") or "",
            location=getattr(machine, "location", "") or "",
            vm_size=self._vm_size(machine),
            public_ip_address=public_ip,
            managed_disk_encryption_enabled=self._os_disk_encryption_enabled(machine),
            system_assigned_identity_enabled=bool(identity_type and "systemassigned" in str(identity_type).lower()),
            network_security_group_ids=nsg_ids,
            tags=dict(getattr(machine, "tags", None) or {}),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    @staticmethod
    def _vm_size(machine) -> str | None:
        hardware_profile = getattr(machine, "hardware_profile", None)
        if hardware_profile is None:
            return None
        return _enum_value(getattr(hardware_profile, "vm_size", None))

    @staticmethod
    def _os_disk_encryption_enabled(machine) -> bool | None:
        storage_profile = getattr(machine, "storage_profile", None)
        os_disk = getattr(storage_profile, "os_disk", None) if storage_profile is not None else None
        managed_disk = getattr(os_disk, "managed_disk", None) if os_disk is not None else None
        if managed_disk is None:
            return None
        # A disk-encryption-set reference means a customer-managed key
        # is in force. Its absence is NOT proof of no encryption (Azure
        # encrypts managed disks with platform keys by default), so this
        # reports None rather than False — the rule then decides, and
        # rules/azure/compute.yaml documents exactly what it means.
        encryption_set = getattr(managed_disk, "disk_encryption_set", None)
        if encryption_set is None:
            return None
        return bool(getattr(encryption_set, "id", None))

    def _resolve_network(self, machine) -> tuple[tuple[str, ...], str | None]:
        network_profile = getattr(machine, "network_profile", None)
        interfaces = getattr(network_profile, "network_interfaces", None) or [] if network_profile else []

        nsg_ids: list[str] = []
        public_ip: str | None = None

        for interface_reference in interfaces:
            interface = self._get_interface(getattr(interface_reference, "id", None))
            if interface is None:
                continue

            nsg = getattr(interface, "network_security_group", None)
            nsg_id = getattr(nsg, "id", None) if nsg is not None else None
            if nsg_id:
                nsg_ids.append(nsg_id)

            for ip_configuration in getattr(interface, "ip_configurations", None) or []:
                subnet_nsg_id = self._subnet_nsg_id(ip_configuration)
                if subnet_nsg_id:
                    nsg_ids.append(subnet_nsg_id)

                if public_ip is None:
                    public_ip = self._public_ip_address(ip_configuration)

        # Deduplicate while preserving first-seen order, so collection
        # stays deterministic (a set would not be).
        unique_nsg_ids = tuple(dict.fromkeys(nsg_ids))
        return unique_nsg_ids, public_ip

    def _get_interface(self, interface_id: str | None):
        if not interface_id:
            return None
        resource_group = _resource_group_from_id(interface_id)
        name = interface_id.rsplit("/", 1)[-1]
        if not resource_group or not name:
            return None
        try:
            return self._clients.network.network_interfaces.get(resource_group, name)
        except Exception:
            return None

    def _subnet_nsg_id(self, ip_configuration) -> str | None:
        subnet = getattr(ip_configuration, "subnet", None)
        subnet_id = getattr(subnet, "id", None) if subnet is not None else None
        if not subnet_id:
            return None

        # A subnet reference on a NIC is usually just an id; the NSG
        # association lives on the full subnet object, which needs its
        # own lookup.
        nsg = getattr(subnet, "network_security_group", None)
        if nsg is not None and getattr(nsg, "id", None):
            return nsg.id

        resource_group = _resource_group_from_id(subnet_id)
        parts = subnet_id.split("/")
        try:
            vnet_name = parts[parts.index("virtualNetworks") + 1]
        except (ValueError, IndexError):
            return None
        subnet_name = parts[-1]
        if not resource_group:
            return None
        try:
            full_subnet = self._clients.network.subnets.get(resource_group, vnet_name, subnet_name)
        except Exception:
            return None
        subnet_nsg = getattr(full_subnet, "network_security_group", None)
        return getattr(subnet_nsg, "id", None) if subnet_nsg is not None else None

    def _public_ip_address(self, ip_configuration) -> str | None:
        public_ip_reference = getattr(ip_configuration, "public_ip_address", None)
        if public_ip_reference is None:
            return None

        address = getattr(public_ip_reference, "ip_address", None)
        if address:
            return address

        public_ip_id = getattr(public_ip_reference, "id", None)
        if not public_ip_id:
            return None
        resource_group = _resource_group_from_id(public_ip_id)
        name = public_ip_id.rsplit("/", 1)[-1]
        if not resource_group or not name:
            return None
        try:
            public_ip = self._clients.network.public_ip_addresses.get(resource_group, name)
        except Exception:
            return None
        return getattr(public_ip, "ip_address", None)


def _enum_value(value):
    return getattr(value, "value", value)


def _resource_group_from_id(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return None
