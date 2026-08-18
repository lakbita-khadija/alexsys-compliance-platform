"""AWS CloudTrail trail -> ``NormalizedResource``.

Compliant/non-compliant semantics grounded directly in blueprint §15's
Terraform module table: "multi-région, validation activée" (compliant)
vs "mono-région" (non-compliant) — both captured as plain attributes,
left for a Rule to judge.

The trail's target S3 bucket becomes an ``ACCESSES`` relationship to
that bucket's own ``NormalizedResource`` (Phase 3B scoping decision:
this is the one CloudTrail cross-resource edge real collected data
supports — the bucket is already collected by ``S3Collector`` in the
same scan, so this never risks the ``__internet__``/
``GraphIntegrityViolation`` problem documented in ``normalizers/s3.py``).
No edge is emitted when ``s3_bucket_name`` is absent.
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId


def normalize_cloudtrail_trail(
    *,
    trail_arn: str,
    name: str,
    region: str,
    is_multi_region_trail: bool,
    log_file_validation_enabled: bool,
    is_logging: bool,
    s3_bucket_name: str | None,
    kms_key_id: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    relationships: tuple[ResourceRelationship, ...] = ()
    if s3_bucket_name:
        relationships = (
            ResourceRelationship(
                target_resource_id=ResourceId(s3_bucket_name),
                relationship_type=RelationshipType.ACCESSES,
            ),
        )

    return NormalizedResource(
        resource_id=ResourceId(trail_arn),
        resource_type="cloudtrail",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes={
            "name": name,
            "is_multi_region_trail": is_multi_region_trail,
            "log_file_validation_enabled": log_file_validation_enabled,
            "is_logging": is_logging,
            "s3_bucket_name": s3_bucket_name,
            "kms_key_id": kms_key_id,
        },
        tags={},
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )
