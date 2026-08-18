"""Azure Storage Account -> ``NormalizedResource``.

The Azure counterpart of ``normalizers/s3.py``. Critically, the OUTPUT
shape is provider-neutral: a ``NormalizedResource`` with
``cloud_provider=AZURE`` and plain attribute values. The Rule Engine,
ResourceGraph, and Finding pipeline downstream need zero Azure-specific
code — which is the whole point of normalizing here (blueprint §8).

Attribute naming follows Azure's own vocabulary rather than being
force-mapped onto the S3 names (``https_only`` not ``encrypted``,
``allow_blob_public_access`` not ``public``). Two reasons: the concepts
genuinely differ (an Azure storage account is always encrypted at rest,
so an ``encrypted`` field would be a meaningless constant), and a rule
author reading ``rules/azure/storage.yaml`` should see the same names
the Azure portal shows them. Cross-provider rules are not attempted —
a rule targets one provider's resource_type, and that is deliberate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId


def normalize_storage_account(
    *,
    resource_id: str,
    name: str,
    location: str,
    https_only: bool,
    allow_blob_public_access: bool | None,
    minimum_tls_version: str | None,
    network_default_action: str | None,
    infrastructure_encryption_enabled: bool | None,
    blob_soft_delete_enabled: bool | None,
    tags: Mapping[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="azure_storage_account",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        region=location,
        attributes={
            "name": name,
            # `supportsHttpsTrafficOnly` in the Azure API.
            "https_only": https_only,
            # None when the property is absent from the API response —
            # a genuinely uncollected fact, distinct from False. The
            # rule engine's three-valued logic relies on this
            # distinction (see domain/rules/conditions.py).
            "allow_blob_public_access": allow_blob_public_access,
            "minimum_tls_version": minimum_tls_version,
            # "Deny" means the account's firewall denies by default —
            # the compliant posture. "Allow" means open to all networks.
            "network_default_action": network_default_action,
            "infrastructure_encryption_enabled": infrastructure_encryption_enabled,
            "blob_soft_delete_enabled": blob_soft_delete_enabled,
        },
        tags=dict(tags),
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
