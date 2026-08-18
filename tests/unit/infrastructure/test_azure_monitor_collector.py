from datetime import datetime, timezone

import pytest

from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzurePermissionError
from infrastructure.cloud.azure.resource_collectors.monitor import ActivityLogSettingCollector

TENANT = TenantId("acme")
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

SETTING_ID = f"/subscriptions/{SUBSCRIPTION}/providers/microsoft.insights/diagnosticSettings/activity-log-export"
STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/auditlogs"
)


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class FakeRetentionPolicy:
    def __init__(self, days):
        self.days = days


class FakeLog:
    def __init__(self, category, enabled=True, retention_days=None):
        self.category = category
        self.enabled = enabled
        self.retention_policy = FakeRetentionPolicy(retention_days) if retention_days is not None else None


class FakeSetting:
    def __init__(
        self,
        resource_id=SETTING_ID,
        name="activity-log-export",
        storage_account_id=STORAGE_ID,
        workspace_id=None,
        event_hub_authorization_rule_id=None,
        logs=None,
    ):
        self.id = resource_id
        self.name = name
        self.storage_account_id = storage_account_id
        self.workspace_id = workspace_id
        self.event_hub_authorization_rule_id = event_hub_authorization_rule_id
        self.logs = logs if logs is not None else [FakeLog("Administrative", retention_days=365)]


class FakeSettingOperations:
    def __init__(self, settings, error=None):
        self._settings = settings
        self._error = error

    def list(self, resource_uri):
        if self._error is not None:
            raise self._error
        return iter(self._settings)


class FakeMonitorClient:
    def __init__(self, settings, error=None):
        self.subscription_diagnostic_settings = FakeSettingOperations(settings, error)


class FakeClients:
    def __init__(self, monitor):
        self.subscription_id = SUBSCRIPTION
        self.monitor = monitor
        self.storage = None
        self.network = None
        self.compute = None
        self.keyvault = None


def make_collector(settings, error=None):
    return ActivityLogSettingCollector(
        clients=FakeClients(FakeMonitorClient(settings, error)), tenant_id=TENANT, clock=CLOCK
    )


class TestActivityLogSettingCollectorBasics:
    def test_collects_a_compliant_setting(self) -> None:
        resource = make_collector([FakeSetting()]).collect()[0]
        assert resource.resource_id == ResourceId(SETTING_ID)
        assert resource.resource_type == "azure_activity_log_setting"
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.attributes["storage_account_id"] == STORAGE_ID
        assert resource.attributes["has_any_destination"] is True
        assert resource.attributes["retention_days"] == 365
        assert resource.attributes["enabled_log_categories"] == ("Administrative",)

    def test_diagnostic_settings_are_subscription_scoped_not_regional(self) -> None:
        resource = make_collector([FakeSetting()]).collect()[0]
        assert resource.region is None

    def test_subscription_id_becomes_account_id(self) -> None:
        resource = make_collector([FakeSetting()]).collect()[0]
        assert resource.account_id == SUBSCRIPTION

    def test_no_settings_returns_empty_tuple(self) -> None:
        assert make_collector([]).collect() == ()

    def test_only_enabled_categories_are_reported(self) -> None:
        logs = [FakeLog("Administrative", enabled=True), FakeLog("Security", enabled=False)]
        resource = make_collector([FakeSetting(logs=logs)]).collect()[0]
        assert resource.attributes["enabled_log_categories"] == ("Administrative",)

    def test_workspace_destination_counts_as_a_destination(self) -> None:
        setting = FakeSetting(storage_account_id=None, workspace_id="/subscriptions/x/workspaces/law-1")
        resource = make_collector([setting]).collect()[0]
        assert resource.attributes["has_any_destination"] is True

    def test_setting_with_no_destination_at_all(self) -> None:
        setting = FakeSetting(storage_account_id=None)
        resource = make_collector([setting]).collect()[0]
        assert resource.attributes["has_any_destination"] is False


class TestActivityLogAccessesStorageRelationship:
    def test_storage_destination_becomes_an_accesses_relationship(self) -> None:
        resource = make_collector([FakeSetting()]).collect()[0]
        assert len(resource.relationships) == 1
        relationship = resource.relationships[0]
        assert relationship.relationship_type is RelationshipType.ACCESSES
        assert relationship.target_resource_id == ResourceId(STORAGE_ID)

    def test_no_storage_destination_means_no_relationship(self) -> None:
        resource = make_collector([FakeSetting(storage_account_id=None)]).collect()[0]
        assert resource.relationships == ()


class TestActivityLogRetention:
    def test_longest_retention_across_enabled_categories_is_reported(self) -> None:
        logs = [FakeLog("Administrative", retention_days=90), FakeLog("Security", retention_days=365)]
        resource = make_collector([FakeSetting(logs=logs)]).collect()[0]
        assert resource.attributes["retention_days"] == 365

    def test_disabled_category_retention_is_ignored(self) -> None:
        logs = [FakeLog("Administrative", enabled=True, retention_days=30), FakeLog("Security", enabled=False, retention_days=365)]
        resource = make_collector([FakeSetting(logs=logs)]).collect()[0]
        assert resource.attributes["retention_days"] == 30

    def test_no_retention_policy_is_none_not_zero(self) -> None:
        logs = [FakeLog("Administrative", retention_days=None)]
        resource = make_collector([FakeSetting(logs=logs)]).collect()[0]
        assert resource.attributes["retention_days"] is None


class TestActivityLogCollectorErrors:
    def test_permission_error_is_translated_and_wrapped(self) -> None:
        with pytest.raises(AzureCollectionError) as exc_info:
            make_collector([], error=FakeHttpError(403)).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)


class TestActivityLogCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        setting = FakeSetting()
        assert make_collector([setting]).collect() == make_collector([setting]).collect()
