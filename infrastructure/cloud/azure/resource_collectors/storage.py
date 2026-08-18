"""Azure Storage Account collection."""

from __future__ import annotations

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.storage import normalize_storage_account
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector


class StorageAccountCollector(AzureResourceCollector):
    """Collects every storage account in the subscription.

    ``storage_accounts.list()`` returns an iterable pager the SDK
    advances transparently, so there is no explicit pagination loop
    here (unlike boto3, which requires an explicit paginator).
    """

    resource_type = "storage accounts"

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context="collecting storage accounts")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        accounts = list(self._clients.storage.storage_accounts.list())
        return tuple(self._normalize(account, collected_at) for account in accounts)

    def _normalize(self, account, collected_at) -> NormalizedResource:
        network_rule_set = getattr(account, "network_rule_set", None)
        encryption = getattr(account, "encryption", None)

        return normalize_storage_account(
            resource_id=account.id,
            name=getattr(account, "name", "") or "",
            location=getattr(account, "location", "") or "",
            https_only=bool(getattr(account, "enable_https_traffic_only", False)),
            allow_blob_public_access=getattr(account, "allow_blob_public_access", None),
            minimum_tls_version=getattr(account, "minimum_tls_version", None),
            network_default_action=_default_action(network_rule_set),
            infrastructure_encryption_enabled=getattr(encryption, "require_infrastructure_encryption", None)
            if encryption is not None
            else None,
            blob_soft_delete_enabled=self._blob_soft_delete_enabled(account),
            tags=dict(getattr(account, "tags", None) or {}),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    def _blob_soft_delete_enabled(self, account) -> bool | None:
        """Blob soft-delete lives on a separate ``blob_services`` API,
        not on the storage account itself. A failure to read it (most
        often a missing data-plane role) yields ``None`` — genuinely
        uncollected — rather than ``False``, which would report a
        violation this collector never actually observed.
        """

        resource_group = _resource_group_from_id(account.id)
        if resource_group is None:
            return None
        try:
            properties = self._clients.storage.blob_services.get_service_properties(
                resource_group_name=resource_group,
                account_name=account.name,
            )
        except Exception:
            return None
        delete_policy = getattr(properties, "delete_retention_policy", None)
        if delete_policy is None:
            return None
        return bool(getattr(delete_policy, "enabled", False))


def _default_action(network_rule_set) -> str | None:
    if network_rule_set is None:
        return None
    action = getattr(network_rule_set, "default_action", None)
    if action is None:
        return None
    # The SDK may return an enum or a plain string depending on version.
    return getattr(action, "value", action)


def _resource_group_from_id(resource_id: str | None) -> str | None:
    """Extracts the resource group from an ARM resource id of the form
    ``/subscriptions/<sub>/resourceGroups/<rg>/providers/...``.
    Returns ``None`` for any id that doesn't carry one.
    """

    if not resource_id:
        return None
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return None
