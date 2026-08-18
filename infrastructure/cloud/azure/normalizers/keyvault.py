"""Azure Key Vault -> ``NormalizedResource``.

The Azure counterpart of ``normalizers/kms.py``. Key Vault is the
closest Azure analogue of KMS for CSPM purposes: it holds the keys,
secrets, and certificates whose exposure or accidental deletion is the
security event worth detecting.

``soft_delete_enabled``/``purge_protection_enabled`` are the direct
counterparts of the KMS ``PendingDeletion`` concern — they are what
makes a deleted vault (and everything in it) recoverable rather than
irreversibly gone.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId


def normalize_key_vault(
    *,
    resource_id: str,
    name: str,
    location: str,
    soft_delete_enabled: bool | None,
    purge_protection_enabled: bool | None,
    rbac_authorization_enabled: bool | None,
    public_network_access_enabled: bool | None,
    network_default_action: str | None,
    tags: Mapping[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="azure_key_vault",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        region=location,
        attributes={
            "name": name,
            "soft_delete_enabled": soft_delete_enabled,
            "purge_protection_enabled": purge_protection_enabled,
            # RBAC authorization is the modern, auditable access model;
            # the legacy alternative is per-vault access policies.
            "rbac_authorization_enabled": rbac_authorization_enabled,
            "public_network_access_enabled": public_network_access_enabled,
            "network_default_action": network_default_action,
        },
        tags=dict(tags),
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
