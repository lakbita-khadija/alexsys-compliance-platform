from datetime import datetime, timezone

import pytest

from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzurePermissionError
from infrastructure.cloud.azure.normalizers.network import analyze_security_rules
from infrastructure.cloud.azure.resource_collectors.network import NetworkSecurityGroupCollector

TENANT = TenantId("acme")
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

NSG_ID = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/nsg-1"


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class FakeSecurityRule:
    def __init__(
        self,
        name="rule",
        direction="Inbound",
        access="Allow",
        protocol="Tcp",
        priority=100,
        source_address_prefix="*",
        source_address_prefixes=None,
        destination_port_range="22",
        destination_port_ranges=None,
    ):
        self.name = name
        self.direction = direction
        self.access = access
        self.protocol = protocol
        self.priority = priority
        self.source_address_prefix = source_address_prefix
        self.source_address_prefixes = source_address_prefixes
        self.destination_port_range = destination_port_range
        self.destination_port_ranges = destination_port_ranges


class FakeNsg:
    def __init__(self, resource_id=NSG_ID, name="nsg-1", location="westeurope", rules=None, tags=None):
        self.id = resource_id
        self.name = name
        self.location = location
        self.security_rules = rules or []
        self.tags = tags or {}


class FakeNsgOperations:
    def __init__(self, groups, error=None):
        self._groups = groups
        self._error = error

    def list_all(self):
        if self._error is not None:
            raise self._error
        return iter(self._groups)


class FakeNetworkClient:
    def __init__(self, groups, error=None):
        self.network_security_groups = FakeNsgOperations(groups, error)


class FakeClients:
    def __init__(self, network):
        self.subscription_id = SUBSCRIPTION
        self.network = network
        self.storage = None
        self.compute = None
        self.keyvault = None
        self.monitor = None


def make_collector(groups, error=None):
    return NetworkSecurityGroupCollector(
        clients=FakeClients(FakeNetworkClient(groups, error)), tenant_id=TENANT, clock=CLOCK
    )


class TestAnalyzeSecurityRules:
    """Direct tests of the pure analysis function — the Azure analogue
    of the AWS normalizer's `analyze_ingress_rules`.
    """

    def test_inbound_allow_from_wildcard_is_unrestricted(self) -> None:
        has_unrestricted, ports = analyze_security_rules(
            [{"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}]
        )
        assert has_unrestricted is True
        assert ports == (22,)

    def test_internet_source_is_unrestricted(self) -> None:
        has_unrestricted, ports = analyze_security_rules(
            [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "3389",
                }
            ]
        )
        assert has_unrestricted is True
        assert ports == (3389,)

    def test_zero_cidr_source_is_unrestricted(self) -> None:
        has_unrestricted, _ = analyze_security_rules(
            [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "80",
                }
            ]
        )
        assert has_unrestricted is True

    def test_deny_rule_is_ignored(self) -> None:
        has_unrestricted, ports = analyze_security_rules(
            [{"direction": "Inbound", "access": "Deny", "source_address_prefix": "*", "destination_port_range": "22"}]
        )
        assert has_unrestricted is False
        assert ports == ()

    def test_outbound_rule_is_ignored(self) -> None:
        has_unrestricted, _ = analyze_security_rules(
            [{"direction": "Outbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "22"}]
        )
        assert has_unrestricted is False

    def test_scoped_source_is_not_unrestricted(self) -> None:
        has_unrestricted, _ = analyze_security_rules(
            [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "10.0.0.0/16",
                    "destination_port_range": "22",
                }
            ]
        )
        assert has_unrestricted is False

    def test_port_range_sets_flag_without_enumerating_ports(self) -> None:
        has_unrestricted, ports = analyze_security_rules(
            [{"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "20-25"}]
        )
        assert has_unrestricted is True
        assert ports == ()

    def test_wildcard_port_sets_flag_without_enumerating_ports(self) -> None:
        has_unrestricted, ports = analyze_security_rules(
            [{"direction": "Inbound", "access": "Allow", "source_address_prefix": "*", "destination_port_range": "*"}]
        )
        assert has_unrestricted is True
        assert ports == ()

    def test_multiple_destination_port_ranges_are_all_considered(self) -> None:
        _, ports = analyze_security_rules(
            [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "*",
                    "destination_port_ranges": ["22", "3389"],
                }
            ]
        )
        assert set(ports) == {22, 3389}

    def test_source_address_prefixes_list_is_considered(self) -> None:
        has_unrestricted, _ = analyze_security_rules(
            [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefixes": ["10.0.0.0/8", "*"],
                    "destination_port_range": "22",
                }
            ]
        )
        assert has_unrestricted is True

    def test_no_rules_is_not_unrestricted(self) -> None:
        assert analyze_security_rules([]) == (False, ())


class TestNetworkSecurityGroupCollector:
    def test_collects_a_restrictive_nsg(self) -> None:
        rule = FakeSecurityRule(source_address_prefix="10.0.0.0/16", destination_port_range="443")
        resource = make_collector([FakeNsg(rules=[rule])]).collect()[0]
        assert resource.resource_id == ResourceId(NSG_ID)
        assert resource.resource_type == "azure_network_security_group"
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.attributes["has_unrestricted_ingress"] is False
        assert resource.attributes["unrestricted_ingress_ports"] == ()

    def test_collects_an_open_nsg(self) -> None:
        resource = make_collector([FakeNsg(rules=[FakeSecurityRule()])]).collect()[0]
        assert resource.attributes["has_unrestricted_ingress"] is True
        assert resource.attributes["unrestricted_ingress_ports"] == (22,)

    def test_security_rule_count_is_reported(self) -> None:
        rules = [FakeSecurityRule(name=f"r{i}") for i in range(3)]
        resource = make_collector([FakeNsg(rules=rules)]).collect()[0]
        assert resource.attributes["security_rule_count"] == 3

    def test_subscription_id_becomes_account_id(self) -> None:
        resource = make_collector([FakeNsg()]).collect()[0]
        assert resource.account_id == SUBSCRIPTION

    def test_empty_subscription_returns_empty_tuple(self) -> None:
        assert make_collector([]).collect() == ()

    def test_permission_error_is_translated_and_wrapped(self) -> None:
        with pytest.raises(AzureCollectionError) as exc_info:
            make_collector([], error=FakeHttpError(403)).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)

    def test_collection_is_deterministic(self) -> None:
        nsg = FakeNsg(rules=[FakeSecurityRule()])
        assert make_collector([nsg]).collect() == make_collector([nsg]).collect()
