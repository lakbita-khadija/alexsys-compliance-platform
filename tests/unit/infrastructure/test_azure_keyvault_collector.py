from datetime import datetime, timezone

import pytest

from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzurePermissionError
from infrastructure.cloud.azure.resource_collectors.keyvault import KeyVaultCollector

TENANT = TenantId("acme")
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

VAULT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-compliant"
)


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class FakeNetworkAcls:
    def __init__(self, default_action):
        self.default_action = default_action


class FakeVaultProperties:
    def __init__(
        self,
        soft_delete=True,
        purge_protection=True,
        rbac=True,
        public_network_access="Disabled",
        default_action="Deny",
    ):
        self.enable_soft_delete = soft_delete
        self.enable_purge_protection = purge_protection
        self.enable_rbac_authorization = rbac
        self.public_network_access = public_network_access
        self.network_acls = FakeNetworkAcls(default_action) if default_action else None


class FakeVaultSummary:
    def __init__(self, resource_id=VAULT_ID, name="kv-compliant", location="westeurope", tags=None):
        self.id = resource_id
        self.name = name
        self.location = location
        self.tags = tags or {}


class FakeVaultDetailed(FakeVaultSummary):
    def __init__(self, properties=None, **kwargs):
        super().__init__(**kwargs)
        self.properties = properties or FakeVaultProperties()


class FakeVaultOperations:
    def __init__(self, vaults, detailed_by_name=None, list_error=None, get_error=None):
        self._vaults = vaults
        self._detailed_by_name = detailed_by_name or {}
        self._list_error = list_error
        self._get_error = get_error

    def list(self):
        if self._list_error is not None:
            raise self._list_error
        return iter(self._vaults)

    def get(self, resource_group, name):
        if self._get_error is not None:
            raise self._get_error
        if name not in self._detailed_by_name:
            raise FakeHttpError(404)
        return self._detailed_by_name[name]


class FakeKeyVaultClient:
    def __init__(self, vaults, detailed_by_name=None, list_error=None, get_error=None):
        self.vaults = FakeVaultOperations(vaults, detailed_by_name, list_error, get_error)


class FakeClients:
    def __init__(self, keyvault):
        self.subscription_id = SUBSCRIPTION
        self.keyvault = keyvault
        self.storage = None
        self.network = None
        self.compute = None
        self.monitor = None


def make_collector(vaults, detailed_by_name=None, list_error=None, get_error=None):
    clients = FakeClients(FakeKeyVaultClient(vaults, detailed_by_name, list_error, get_error))
    return KeyVaultCollector(clients=clients, tenant_id=TENANT, clock=CLOCK)


class TestKeyVaultCollectorBasics:
    def test_collects_a_compliant_vault(self) -> None:
        detailed = FakeVaultDetailed()
        resource = make_collector([FakeVaultSummary()], {"kv-compliant": detailed}).collect()[0]
        assert resource.resource_id == ResourceId(VAULT_ID)
        assert resource.resource_type == "azure_key_vault"
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.attributes["soft_delete_enabled"] is True
        assert resource.attributes["purge_protection_enabled"] is True
        assert resource.attributes["rbac_authorization_enabled"] is True
        assert resource.attributes["public_network_access_enabled"] is False
        assert resource.attributes["network_default_action"] == "Deny"

    def test_collects_a_noncompliant_vault(self) -> None:
        properties = FakeVaultProperties(
            soft_delete=False,
            purge_protection=False,
            rbac=False,
            public_network_access="Enabled",
            default_action="Allow",
        )
        detailed = FakeVaultDetailed(properties=properties)
        resource = make_collector([FakeVaultSummary()], {"kv-compliant": detailed}).collect()[0]
        assert resource.attributes["soft_delete_enabled"] is False
        assert resource.attributes["purge_protection_enabled"] is False
        assert resource.attributes["rbac_authorization_enabled"] is False
        assert resource.attributes["public_network_access_enabled"] is True
        assert resource.attributes["network_default_action"] == "Allow"

    def test_subscription_id_becomes_account_id(self) -> None:
        resource = make_collector([FakeVaultSummary()], {"kv-compliant": FakeVaultDetailed()}).collect()[0]
        assert resource.account_id == SUBSCRIPTION

    def test_empty_subscription_returns_empty_tuple(self) -> None:
        assert make_collector([]).collect() == ()

    def test_multiple_vaults_are_all_collected(self) -> None:
        vaults = [FakeVaultSummary(resource_id=f"{VAULT_ID}-{i}", name=f"kv{i}") for i in range(3)]
        detailed = {f"kv{i}": FakeVaultDetailed(name=f"kv{i}") for i in range(3)}
        assert len(make_collector(vaults, detailed).collect()) == 3


class TestKeyVaultUncollectedFacts:
    def test_failed_detail_lookup_falls_back_to_the_summary(self) -> None:
        # The vault is still reported; its unreadable properties become
        # None (uncollected) rather than fabricated defaults.
        resource = make_collector([FakeVaultSummary()], get_error=FakeHttpError(403)).collect()[0]
        assert resource.resource_id == ResourceId(VAULT_ID)
        assert resource.attributes["soft_delete_enabled"] is None
        assert resource.attributes["purge_protection_enabled"] is None

    def test_absent_public_network_access_is_none(self) -> None:
        properties = FakeVaultProperties(public_network_access=None)
        detailed = FakeVaultDetailed(properties=properties)
        resource = make_collector([FakeVaultSummary()], {"kv-compliant": detailed}).collect()[0]
        assert resource.attributes["public_network_access_enabled"] is None

    def test_absent_network_acls_is_none(self) -> None:
        properties = FakeVaultProperties(default_action=None)
        detailed = FakeVaultDetailed(properties=properties)
        resource = make_collector([FakeVaultSummary()], {"kv-compliant": detailed}).collect()[0]
        assert resource.attributes["network_default_action"] is None


class TestKeyVaultCollectorErrors:
    def test_permission_error_is_translated_and_wrapped(self) -> None:
        with pytest.raises(AzureCollectionError) as exc_info:
            make_collector([], list_error=FakeHttpError(403)).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)


class TestKeyVaultCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        summary = FakeVaultSummary()
        detailed = {"kv-compliant": FakeVaultDetailed()}
        assert make_collector([summary], detailed).collect() == make_collector([summary], detailed).collect()
