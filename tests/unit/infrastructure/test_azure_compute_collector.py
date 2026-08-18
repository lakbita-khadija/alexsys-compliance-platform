from datetime import datetime, timezone

import pytest

from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzurePermissionError
from infrastructure.cloud.azure.resource_collectors.compute import VirtualMachineCollector

TENANT = TenantId("acme")
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

_RG = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-test/providers"
VM_ID = f"{_RG}/Microsoft.Compute/virtualMachines/vm-1"
NIC_ID = f"{_RG}/Microsoft.Network/networkInterfaces/nic-1"
NSG_ID = f"{_RG}/Microsoft.Network/networkSecurityGroups/nsg-1"
SUBNET_NSG_ID = f"{_RG}/Microsoft.Network/networkSecurityGroups/nsg-subnet"
SUBNET_ID = f"{_RG}/Microsoft.Network/virtualNetworks/vnet-1/subnets/subnet-1"
PUBLIC_IP_ID = f"{_RG}/Microsoft.Network/publicIPAddresses/pip-1"


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class Ref:
    def __init__(self, resource_id=None, **kwargs):
        self.id = resource_id
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeIpConfiguration:
    def __init__(self, subnet=None, public_ip_address=None):
        self.subnet = subnet
        self.public_ip_address = public_ip_address


class FakeNic:
    def __init__(self, network_security_group=None, ip_configurations=None):
        self.network_security_group = network_security_group
        self.ip_configurations = ip_configurations or []


class FakeVm:
    def __init__(
        self,
        resource_id=VM_ID,
        name="vm-1",
        location="westeurope",
        vm_size="Standard_B1s",
        nic_ids=(NIC_ID,),
        identity_type=None,
        disk_encryption_set_id=None,
        has_managed_disk=True,
        tags=None,
    ):
        self.id = resource_id
        self.name = name
        self.location = location
        self.hardware_profile = Ref(vm_size=vm_size)
        self.network_profile = Ref(network_interfaces=[Ref(resource_id=nic_id) for nic_id in nic_ids])
        self.identity = Ref(type=identity_type) if identity_type else None
        managed_disk = None
        if has_managed_disk:
            encryption_set = Ref(resource_id=disk_encryption_set_id) if disk_encryption_set_id else None
            managed_disk = Ref(disk_encryption_set=encryption_set)
        self.storage_profile = Ref(os_disk=Ref(managed_disk=managed_disk))
        self.tags = tags or {}


class FakeVmOperations:
    def __init__(self, machines, error=None):
        self._machines = machines
        self._error = error

    def list_all(self):
        if self._error is not None:
            raise self._error
        return iter(self._machines)


class FakeComputeClient:
    def __init__(self, machines, error=None):
        self.virtual_machines = FakeVmOperations(machines, error)


class FakeNicOperations:
    def __init__(self, nics_by_name, error=None):
        self._nics_by_name = nics_by_name
        self._error = error

    def get(self, resource_group, name):
        if self._error is not None:
            raise self._error
        if name not in self._nics_by_name:
            raise FakeHttpError(404)
        return self._nics_by_name[name]


class FakeSubnetOperations:
    def __init__(self, subnets_by_name):
        self._subnets_by_name = subnets_by_name

    def get(self, resource_group, vnet_name, subnet_name):
        if subnet_name not in self._subnets_by_name:
            raise FakeHttpError(404)
        return self._subnets_by_name[subnet_name]


class FakePublicIpOperations:
    def __init__(self, ips_by_name):
        self._ips_by_name = ips_by_name

    def get(self, resource_group, name):
        if name not in self._ips_by_name:
            raise FakeHttpError(404)
        return self._ips_by_name[name]


class FakeNetworkClient:
    def __init__(self, nics_by_name=None, subnets_by_name=None, ips_by_name=None, nic_error=None):
        self.network_interfaces = FakeNicOperations(nics_by_name or {}, nic_error)
        self.subnets = FakeSubnetOperations(subnets_by_name or {})
        self.public_ip_addresses = FakePublicIpOperations(ips_by_name or {})


class FakeClients:
    def __init__(self, compute, network):
        self.subscription_id = SUBSCRIPTION
        self.compute = compute
        self.network = network
        self.storage = None
        self.keyvault = None
        self.monitor = None


def make_collector(machines, *, error=None, nics=None, subnets=None, ips=None, nic_error=None):
    clients = FakeClients(
        FakeComputeClient(machines, error),
        FakeNetworkClient(nics, subnets, ips, nic_error),
    )
    return VirtualMachineCollector(clients=clients, tenant_id=TENANT, clock=CLOCK)


class TestVirtualMachineCollectorBasics:
    def test_collects_a_virtual_machine(self) -> None:
        resource = make_collector([FakeVm()], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.resource_id == ResourceId(VM_ID)
        assert resource.resource_type == "azure_virtual_machine"
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.region == "westeurope"
        assert resource.attributes["vm_size"] == "Standard_B1s"

    def test_subscription_id_becomes_account_id(self) -> None:
        resource = make_collector([FakeVm()], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.account_id == SUBSCRIPTION

    def test_tags_are_captured(self) -> None:
        resource = make_collector([FakeVm(tags={"env": "test"})], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.tags == {"env": "test"}

    def test_empty_subscription_returns_empty_tuple(self) -> None:
        assert make_collector([]).collect() == ()


class TestVirtualMachineIdentity:
    def test_system_assigned_identity_is_detected(self) -> None:
        vm = FakeVm(identity_type="SystemAssigned")
        resource = make_collector([vm], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["system_assigned_identity_enabled"] is True

    def test_user_assigned_only_identity_is_not_system_assigned(self) -> None:
        vm = FakeVm(identity_type="UserAssigned")
        resource = make_collector([vm], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["system_assigned_identity_enabled"] is False

    def test_no_identity_is_false(self) -> None:
        resource = make_collector([FakeVm()], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["system_assigned_identity_enabled"] is False


class TestVirtualMachineDiskEncryption:
    def test_disk_encryption_set_means_customer_managed_encryption(self) -> None:
        vm = FakeVm(disk_encryption_set_id="/subscriptions/x/des-1")
        resource = make_collector([vm], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["managed_disk_encryption_enabled"] is True

    def test_no_encryption_set_is_none_not_false(self) -> None:
        # Azure encrypts managed disks with platform keys by default,
        # so "no customer key" is not evidence of "no encryption".
        resource = make_collector([FakeVm()], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["managed_disk_encryption_enabled"] is None

    def test_no_managed_disk_is_none(self) -> None:
        vm = FakeVm(has_managed_disk=False)
        resource = make_collector([vm], nics={"nic-1": FakeNic()}).collect()[0]
        assert resource.attributes["managed_disk_encryption_enabled"] is None


class TestVirtualMachineNsgRelationships:
    def test_direct_nic_nsg_becomes_attached_to_relationship(self) -> None:
        nic = FakeNic(network_security_group=Ref(resource_id=NSG_ID))
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        assert len(resource.relationships) == 1
        relationship = resource.relationships[0]
        assert relationship.target_resource_id == ResourceId(NSG_ID)
        assert relationship.relationship_type is RelationshipType.ATTACHED_TO

    def test_subnet_nsg_is_resolved_through_a_subnet_lookup(self) -> None:
        nic = FakeNic(ip_configurations=[FakeIpConfiguration(subnet=Ref(resource_id=SUBNET_ID))])
        subnet = Ref(network_security_group=Ref(resource_id=SUBNET_NSG_ID))
        resource = make_collector([FakeVm()], nics={"nic-1": nic}, subnets={"subnet-1": subnet}).collect()[0]
        targets = {r.target_resource_id for r in resource.relationships}
        assert ResourceId(SUBNET_NSG_ID) in targets

    def test_inline_subnet_nsg_avoids_a_lookup(self) -> None:
        subnet_ref = Ref(resource_id=SUBNET_ID, network_security_group=Ref(resource_id=SUBNET_NSG_ID))
        nic = FakeNic(ip_configurations=[FakeIpConfiguration(subnet=subnet_ref)])
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        targets = {r.target_resource_id for r in resource.relationships}
        assert ResourceId(SUBNET_NSG_ID) in targets

    def test_both_nic_and_subnet_nsgs_are_captured(self) -> None:
        subnet_ref = Ref(resource_id=SUBNET_ID, network_security_group=Ref(resource_id=SUBNET_NSG_ID))
        nic = FakeNic(
            network_security_group=Ref(resource_id=NSG_ID),
            ip_configurations=[FakeIpConfiguration(subnet=subnet_ref)],
        )
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        targets = {r.target_resource_id for r in resource.relationships}
        assert targets == {ResourceId(NSG_ID), ResourceId(SUBNET_NSG_ID)}

    def test_duplicate_nsg_ids_are_deduplicated_deterministically(self) -> None:
        subnet_ref = Ref(resource_id=SUBNET_ID, network_security_group=Ref(resource_id=NSG_ID))
        nic = FakeNic(
            network_security_group=Ref(resource_id=NSG_ID),
            ip_configurations=[FakeIpConfiguration(subnet=subnet_ref)],
        )
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        assert len(resource.relationships) == 1

    def test_vm_with_no_nics_has_no_relationships(self) -> None:
        resource = make_collector([FakeVm(nic_ids=())]).collect()[0]
        assert resource.relationships == ()

    def test_unreadable_nic_is_skipped_without_failing_the_vm(self) -> None:
        # A missing RBAC role on the NIC must not lose the whole VM.
        resource = make_collector([FakeVm()], nic_error=FakeHttpError(403)).collect()[0]
        assert resource.resource_id == ResourceId(VM_ID)
        assert resource.relationships == ()


class TestVirtualMachinePublicIp:
    def test_inline_public_ip_address_is_used(self) -> None:
        nic = FakeNic(ip_configurations=[FakeIpConfiguration(public_ip_address=Ref(ip_address="203.0.113.7"))])
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        assert resource.attributes["public_ip_address"] == "203.0.113.7"

    def test_public_ip_is_resolved_by_lookup_when_only_an_id_is_present(self) -> None:
        nic = FakeNic(ip_configurations=[FakeIpConfiguration(public_ip_address=Ref(resource_id=PUBLIC_IP_ID))])
        ips = {"pip-1": Ref(ip_address="203.0.113.9")}
        resource = make_collector([FakeVm()], nics={"nic-1": nic}, ips=ips).collect()[0]
        assert resource.attributes["public_ip_address"] == "203.0.113.9"

    def test_no_public_ip_is_none(self) -> None:
        nic = FakeNic(ip_configurations=[FakeIpConfiguration()])
        resource = make_collector([FakeVm()], nics={"nic-1": nic}).collect()[0]
        assert resource.attributes["public_ip_address"] is None


class TestVirtualMachineCollectorErrors:
    def test_permission_error_is_translated_and_wrapped(self) -> None:
        with pytest.raises(AzureCollectionError) as exc_info:
            make_collector([], error=FakeHttpError(403)).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)


class TestVirtualMachineCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        vm = FakeVm()
        nic = FakeNic(network_security_group=Ref(resource_id=NSG_ID))
        first = make_collector([vm], nics={"nic-1": nic}).collect()
        second = make_collector([vm], nics={"nic-1": nic}).collect()
        assert first == second
