from datetime import datetime, timezone

import pytest

from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzurePermissionError
from infrastructure.cloud.azure.resource_collectors.storage import StorageAccountCollector

TENANT = TenantId("acme")
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

ACCOUNT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-test"
    "/providers/Microsoft.Storage/storageAccounts/compliantstore"
)


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class FakeEncryption:
    def __init__(self, require_infrastructure_encryption=None):
        self.require_infrastructure_encryption = require_infrastructure_encryption


class FakeNetworkRuleSet:
    def __init__(self, default_action):
        self.default_action = default_action


class FakeStorageAccount:
    def __init__(
        self,
        resource_id=ACCOUNT_ID,
        name="compliantstore",
        location="westeurope",
        https_only=True,
        allow_blob_public_access=False,
        minimum_tls_version="TLS1_2",
        default_action="Deny",
        infrastructure_encryption=True,
        tags=None,
    ):
        self.id = resource_id
        self.name = name
        self.location = location
        self.enable_https_traffic_only = https_only
        self.allow_blob_public_access = allow_blob_public_access
        self.minimum_tls_version = minimum_tls_version
        self.network_rule_set = FakeNetworkRuleSet(default_action) if default_action else None
        self.encryption = FakeEncryption(infrastructure_encryption)
        self.tags = tags or {}


class FakeDeletePolicy:
    def __init__(self, enabled):
        self.enabled = enabled


class FakeServiceProperties:
    def __init__(self, soft_delete_enabled):
        self.delete_retention_policy = FakeDeletePolicy(soft_delete_enabled) if soft_delete_enabled is not None else None


class FakeBlobServices:
    def __init__(self, soft_delete_enabled=True, error=None):
        self._soft_delete_enabled = soft_delete_enabled
        self._error = error

    def get_service_properties(self, resource_group_name, account_name):
        if self._error is not None:
            raise self._error
        return FakeServiceProperties(self._soft_delete_enabled)


class FakeStorageAccounts:
    def __init__(self, accounts, error=None):
        self._accounts = accounts
        self._error = error

    def list(self):
        if self._error is not None:
            raise self._error
        return iter(self._accounts)


class FakeStorageClient:
    def __init__(self, accounts, error=None, soft_delete_enabled=True, blob_error=None):
        self.storage_accounts = FakeStorageAccounts(accounts, error)
        self.blob_services = FakeBlobServices(soft_delete_enabled, blob_error)


class FakeClients:
    def __init__(self, storage):
        self.subscription_id = SUBSCRIPTION
        self.storage = storage
        self.network = None
        self.compute = None
        self.keyvault = None
        self.monitor = None


def make_collector(accounts, error=None, soft_delete_enabled=True, blob_error=None):
    clients = FakeClients(FakeStorageClient(accounts, error, soft_delete_enabled, blob_error))
    return StorageAccountCollector(clients=clients, tenant_id=TENANT, clock=CLOCK)


class TestStorageAccountCollectorBasics:
    def test_collects_a_compliant_storage_account(self) -> None:
        resources = make_collector([FakeStorageAccount()]).collect()
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_id == ResourceId(ACCOUNT_ID)
        assert resource.resource_type == "azure_storage_account"
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.region == "westeurope"
        assert resource.attributes["https_only"] is True
        assert resource.attributes["allow_blob_public_access"] is False
        assert resource.attributes["network_default_action"] == "Deny"
        assert resource.tenant_id == TENANT
        assert resource.collected_at == CLOCK()

    def test_collects_a_noncompliant_storage_account(self) -> None:
        account = FakeStorageAccount(
            name="openstore",
            https_only=False,
            allow_blob_public_access=True,
            minimum_tls_version="TLS1_0",
            default_action="Allow",
            infrastructure_encryption=False,
        )
        resource = make_collector([account]).collect()[0]
        assert resource.attributes["https_only"] is False
        assert resource.attributes["allow_blob_public_access"] is True
        assert resource.attributes["minimum_tls_version"] == "TLS1_0"
        assert resource.attributes["network_default_action"] == "Allow"

    def test_tags_are_captured(self) -> None:
        resource = make_collector([FakeStorageAccount(tags={"env": "test"})]).collect()[0]
        assert resource.tags == {"env": "test"}

    def test_subscription_id_becomes_account_id(self) -> None:
        resource = make_collector([FakeStorageAccount()]).collect()[0]
        assert resource.account_id == SUBSCRIPTION

    def test_empty_subscription_returns_empty_tuple(self) -> None:
        assert make_collector([]).collect() == ()

    def test_multiple_accounts_are_all_collected(self) -> None:
        accounts = [FakeStorageAccount(resource_id=f"{ACCOUNT_ID}-{i}", name=f"store{i}") for i in range(3)]
        assert len(make_collector(accounts).collect()) == 3


class TestStorageAccountUncollectedFacts:
    def test_absent_public_access_property_is_none_not_false(self) -> None:
        account = FakeStorageAccount()
        account.allow_blob_public_access = None
        resource = make_collector([account]).collect()[0]
        assert resource.attributes["allow_blob_public_access"] is None

    def test_blob_soft_delete_failure_yields_none_not_false(self) -> None:
        resource = make_collector([FakeStorageAccount()], blob_error=FakeHttpError(403)).collect()[0]
        assert resource.attributes["blob_soft_delete_enabled"] is None

    def test_blob_soft_delete_is_read_when_available(self) -> None:
        resource = make_collector([FakeStorageAccount()], soft_delete_enabled=True).collect()[0]
        assert resource.attributes["blob_soft_delete_enabled"] is True

    def test_missing_network_rule_set_yields_none(self) -> None:
        resource = make_collector([FakeStorageAccount(default_action=None)]).collect()[0]
        assert resource.attributes["network_default_action"] is None


class TestStorageAccountCollectorErrors:
    def test_permission_error_is_translated_and_wrapped(self) -> None:
        collector = make_collector([], error=FakeHttpError(403))
        with pytest.raises(AzureCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)

    def test_service_error_is_translated_and_wrapped(self) -> None:
        collector = make_collector([], error=FakeHttpError(500))
        with pytest.raises(AzureCollectionError):
            collector.collect()


class TestStorageAccountCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        account = FakeStorageAccount()
        first = make_collector([account]).collect()
        second = make_collector([account]).collect()
        assert first == second
