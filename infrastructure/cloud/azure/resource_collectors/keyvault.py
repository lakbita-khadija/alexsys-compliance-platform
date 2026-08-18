"""Azure Key Vault collection."""

from __future__ import annotations

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.keyvault import normalize_key_vault
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector


class KeyVaultCollector(AzureResourceCollector):
    """Collects every Key Vault in the subscription.

    ``vaults.list()`` returns summary objects that omit most security
    properties, so each vault is re-fetched with ``vaults.get()`` for
    its full ``properties`` — the same shape as the KMS collector's
    ``list_keys`` + ``describe_key`` pairing on the AWS side.
    """

    resource_type = "key vaults"

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context="collecting key vaults")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        vaults = list(self._clients.keyvault.vaults.list())
        return tuple(self._normalize(vault, collected_at) for vault in vaults)

    def _normalize(self, vault, collected_at) -> NormalizedResource:
        detailed = self._get_detailed(vault) or vault
        properties = getattr(detailed, "properties", None)
        network_acls = getattr(properties, "network_acls", None) if properties is not None else None

        return normalize_key_vault(
            resource_id=vault.id,
            name=getattr(vault, "name", "") or "",
            location=getattr(detailed, "location", None) or getattr(vault, "location", "") or "",
            soft_delete_enabled=getattr(properties, "enable_soft_delete", None) if properties else None,
            purge_protection_enabled=getattr(properties, "enable_purge_protection", None) if properties else None,
            rbac_authorization_enabled=getattr(properties, "enable_rbac_authorization", None) if properties else None,
            public_network_access_enabled=_public_network_access(properties),
            network_default_action=_default_action(network_acls),
            tags=dict(getattr(detailed, "tags", None) or getattr(vault, "tags", None) or {}),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    def _get_detailed(self, vault):
        resource_group = _resource_group_from_id(getattr(vault, "id", None))
        name = getattr(vault, "name", None)
        if not resource_group or not name:
            return None
        try:
            return self._clients.keyvault.vaults.get(resource_group, name)
        except Exception:
            return None


def _public_network_access(properties) -> bool | None:
    if properties is None:
        return None
    value = getattr(properties, "public_network_access", None)
    if value is None:
        return None
    return str(_enum_value(value)).lower() == "enabled"


def _default_action(network_acls) -> str | None:
    if network_acls is None:
        return None
    action = getattr(network_acls, "default_action", None)
    if action is None:
        return None
    return _enum_value(action)


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
