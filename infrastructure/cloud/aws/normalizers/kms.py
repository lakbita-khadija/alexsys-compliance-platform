"""AWS KMS key -> ``NormalizedResource``.

Compliant/non-compliant semantics grounded in blueprint §15: "rotation
activée | rotation désactivée". ``rotation_enabled`` is ``None`` (not
``False``) for AWS-managed keys, where rotation status doesn't apply —
never silently reported as "disabled" for a key where the question
doesn't make sense.
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId


def normalize_kms_key(
    *,
    key_arn: str,
    key_state: str,
    key_manager: str,
    rotation_enabled: bool | None,
    key_policy_allows_public_access: bool = False,
    region: str,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(key_arn),
        resource_type="kms_key",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes={
            "key_state": key_state,
            "key_manager": key_manager,
            "rotation_enabled": rotation_enabled,
            # True if the key policy has an unconditional Allow
            # statement granting principal "*" — see
            # `policy_analysis.policy_allows_public_principal`.
            "key_policy_allows_public_access": key_policy_allows_public_access,
        },
        tags={},
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
