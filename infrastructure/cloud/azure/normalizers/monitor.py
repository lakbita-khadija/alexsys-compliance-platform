"""Azure Activity Log diagnostic setting -> ``NormalizedResource``.

The Azure counterpart of ``normalizers/cloudtrail.py``. Azure's
subscription-level Activity Log is always recorded, but it is only
RETAINED beyond its short default window when a diagnostic setting
exports it to a storage account, Log Analytics workspace, or Event Hub
— so the diagnostic setting is the resource whose configuration
actually determines audit coverage, exactly as a CloudTrail trail does.

Like the CloudTrail normalizer, a configured storage-account
destination becomes an ``ACCESSES`` relationship to that storage
account's own ``NormalizedResource``, reusing the existing closed
``RelationshipType`` vocabulary unchanged. No edge is emitted when
there is no storage destination.
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId


def normalize_activity_log_setting(
    *,
    resource_id: str,
    name: str,
    storage_account_id: str | None,
    workspace_id: str | None,
    event_hub_authorization_rule_id: str | None,
    enabled_log_categories: tuple[str, ...],
    retention_days: int | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    relationships: tuple[ResourceRelationship, ...] = ()
    if storage_account_id:
        relationships = (
            ResourceRelationship(
                target_resource_id=ResourceId(storage_account_id),
                relationship_type=RelationshipType.ACCESSES,
            ),
        )

    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="azure_activity_log_setting",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        # Diagnostic settings are subscription-scoped, not regional —
        # `region=None` for the same reason IAM resources use it on the
        # AWS side (see normalizers/iam.py).
        region=None,
        attributes={
            "name": name,
            "storage_account_id": storage_account_id,
            "workspace_id": workspace_id,
            "event_hub_authorization_rule_id": event_hub_authorization_rule_id,
            "enabled_log_categories": enabled_log_categories,
            "has_any_destination": bool(storage_account_id or workspace_id or event_hub_authorization_rule_id),
            "retention_days": retention_days,
        },
        tags={},
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )
