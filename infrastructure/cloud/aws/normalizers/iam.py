"""AWS IAM user -> ``NormalizedResource``.

IAM is global — ``region`` is always ``None``, never forced into a
regional model (Phase 1's ``NormalizedResource.region`` is optional for
exactly this case; see blueprint §8, Phase 1 docs §7 decision 2).
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId


def normalize_iam_user(
    *,
    arn: str,
    mfa_active: bool,
    access_key_count: int,
    active_access_key_count: int,
    attached_policy_names: tuple[str, ...],
    has_full_admin_policy: bool = False,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(arn),
        resource_type="iam_user",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=None,
        attributes={
            "mfa_active": mfa_active,
            "access_key_count": access_key_count,
            "active_access_key_count": active_access_key_count,
            "attached_policy_names": attached_policy_names,
            # True if any attached managed policy's default version
            # grants Action "*" over Resource "*" — see
            # `policy_analysis.policy_grants_full_admin`. Inline user
            # policies are not collected (out of scope for this phase).
            "has_full_admin_policy": has_full_admin_policy,
        },
        tags={},
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )


def normalize_iam_account_summary(
    *,
    account_id: str,
    root_mfa_enabled: bool,
    has_password_policy: bool,
    password_policy_min_length: int | None,
    password_policy_requires_symbols: bool | None,
    password_policy_requires_numbers: bool | None,
    password_policy_max_age_days: int | None,
    password_policy_reuse_prevention: int | None,
    tenant_id: TenantId,
    collected_at: datetime,
) -> NormalizedResource:
    """The account-wide IAM settings that don't belong to any single
    user (blueprint §15's "root MFA" / "password policy" checks).
    ``resource_id`` is the account itself, not a user or role — the one
    resource of this type per scanned account.
    """

    return NormalizedResource(
        resource_id=ResourceId(f"iam-account-summary:{account_id}"),
        resource_type="iam_account_summary",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=None,
        attributes={
            "root_mfa_enabled": root_mfa_enabled,
            "has_password_policy": has_password_policy,
            "password_policy_min_length": password_policy_min_length,
            "password_policy_requires_symbols": password_policy_requires_symbols,
            "password_policy_requires_numbers": password_policy_requires_numbers,
            "password_policy_max_age_days": password_policy_max_age_days,
            "password_policy_reuse_prevention": password_policy_reuse_prevention,
        },
        tags={},
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
