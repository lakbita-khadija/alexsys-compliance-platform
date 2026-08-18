"""AWS S3 bucket -> ``NormalizedResource`` (blueprint §8).

Exposure is captured as a plain ``public: bool`` attribute, not a
``PUBLICLY_EXPOSED`` graph relationship to a special ``__internet__``
node. Blueprint §11 describes that node as created "only when real
exposure is detected" for attack-path discovery — but Phase 2's
``BuildResourceGraph`` never creates it (attack-path discovery itself
is correctly unimplemented, blueprint §11/Phase 1 audit), and the Rule
Engine's ``source: graph`` leaves have an empty function registry
(Phase 1) — nothing could read a graph relationship yet even if one
were built. Emitting it now would raise ``GraphIntegrityViolation`` on
every real public bucket instead of reporting it. Attributes are what
current rules can actually act on.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId


def normalize_s3_bucket(
    *,
    name: str,
    region: str,
    encrypted: bool,
    public: bool,
    public_access_block_enabled: bool,
    versioning_enabled: bool,
    logging_enabled: bool,
    has_bucket_policy: bool = False,
    bucket_policy_allows_public_access: bool = False,
    tags: Mapping[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(name),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes={
            "encrypted": encrypted,
            # `public` reflects ACL grants to the well-known public
            # group URIs only. `bucket_policy_allows_public_access`
            # (Phase 3B) covers the other exposure path — a bucket
            # policy statement with an unconditional wildcard
            # principal — via `policy_analysis.policy_allows_public_principal`.
            # Neither alone is complete IAM policy evaluation; together
            # they cover the two exposure mechanisms this collector
            # actually reads.
            "public": public,
            "public_access_block_enabled": public_access_block_enabled,
            "versioning_enabled": versioning_enabled,
            "logging_enabled": logging_enabled,
            "has_bucket_policy": has_bucket_policy,
            "bucket_policy_allows_public_access": bucket_policy_allows_public_access,
        },
        tags=dict(tags),
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
