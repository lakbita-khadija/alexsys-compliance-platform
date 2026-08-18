"""Which cloud accounts a tenant is allowed to scan (STEP 6.5).

The gap this closes, from `docs/audits/cloud-auth-readiness.md` §4:
`Tenant` was `(id, name)` and nothing anywhere recorded that
ComplianceIQ tenant `acme` owns AWS account `111111111111`. The scanner
therefore *discovered* which account it had authenticated to — via
`sts:GetCallerIdentity` — and used the answer as a **label** on every
collected resource rather than as a **gate**. Point a tenant's scan at
the wrong credentials and that tenant acquires another organization's
entire estate, correctly tenant-tagged, after which every isolation
control downstream protects the wrong data flawlessly.

Two ideas live here and they must not be collapsed:

* :class:`CloudAccountBinding` — the *expectation*. Authoritative
  configuration: "this tenant may scan this account". Never supplied by
  an API caller.
* :class:`AuthenticatedCloudIdentity` — the *observation*. What the
  provider says we actually authenticated as, obtained from
  `sts:GetCallerIdentity` or an Entra token's `tid` claim.

:func:`verify_cloud_identity` compares them. A mismatch raises; it never
degrades to `UNKNOWN`, because `UNKNOWN` means "we could not determine
this resource's state" and this is not a statement about a resource at
all.

Note the name collision this module sits next to: ``TenantId`` is
ComplianceIQ's *customer*, while ``directory_id`` here is Azure's Entra
tenant — a cloud concept. The blueprint is explicit that a cloud account
must never determine ComplianceIQ tenancy, and this module preserves
that: it constrains which accounts a known tenant may reach, and never
derives the tenant from the account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch, InvalidCloudAccountBinding
from domain.shared.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class CloudAccountBinding:
    """Authoritative: this tenant is permitted to scan this account.

    ``account_id`` follows ``ScanTarget``'s existing convention rather
    than inventing a parallel one — the AWS account id, the Azure
    subscription id, and what a GCP project id would occupy. Reusing the
    vocabulary keeps one concept named one way across the codebase.

    ``directory_id`` is the extra identity scope some providers have and
    AWS does not: Azure's Entra tenant. Nullable because it is not
    universal, and **required in practice for Azure** — a subscription
    id alone does not say which directory authenticated.
    """

    tenant_id: TenantId
    provider: CloudProvider
    account_id: str
    directory_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.provider, CloudProvider):
            raise InvalidCloudAccountBinding("provider must be a CloudProvider")
        if not isinstance(self.account_id, str) or not self.account_id.strip():
            raise InvalidCloudAccountBinding("account_id must be a non-blank string")
        if self.directory_id is not None and (
            not isinstance(self.directory_id, str) or not self.directory_id.strip()
        ):
            raise InvalidCloudAccountBinding(
                "directory_id must be None or a non-blank string"
            )
        # Azure without a directory is a binding that cannot be fully
        # checked: the subscription would match while the authenticating
        # Entra tenant went unverified, which is precisely the hole the
        # audit found (cloud-auth-readiness.md §3.2). Refuse to store a
        # binding that cannot answer the question it exists to answer.
        if self.provider is CloudProvider.AZURE and self.directory_id is None:
            raise InvalidCloudAccountBinding(
                "an Azure binding must name its directory (Entra tenant) id; "
                "a subscription id alone cannot verify which directory authenticated"
            )


@dataclass(frozen=True, slots=True)
class AuthenticatedCloudIdentity:
    """What the provider says we actually are.

    Produced by an adapter that asked the provider — never assembled
    from configuration. The distinction is the whole point: configuration
    is what we *intended*, this is what we *got*.
    """

    provider: CloudProvider
    account_id: str
    directory_id: str | None = None
    #: Opaque principal identifier (an IAM role/user ARN, an Entra object
    #: id). Recorded for the audit trail. Never a credential.
    principal: str | None = None


def verify_cloud_identity(
    *,
    tenant_id: TenantId,
    actual: AuthenticatedCloudIdentity,
    bindings: Iterable[CloudAccountBinding],
) -> CloudAccountBinding:
    """Return the binding that authorizes this identity, or raise.

    Raises :class:`CloudIdentityMismatch` when the tenant has no binding
    for the provider, or when the authenticated account (and, for Azure,
    directory) is not among the ones it is allowed to scan.

    A tenant with **no** bindings is rejected rather than allowed. An
    empty allow-list means "nothing is permitted"; reading it as "no
    restriction" would make the whole mechanism fail open, and a control
    that fails open on a missing configuration is worse than no control,
    because it looks like one.
    """

    candidates = [b for b in bindings if b.tenant_id == tenant_id and b.provider is actual.provider]

    if not candidates:
        raise CloudIdentityMismatch(
            f"tenant {tenant_id!s} has no configured {actual.provider.value} account binding; "
            "refusing to scan an account it is not declared to own"
        )

    for binding in candidates:
        if binding.account_id != actual.account_id:
            continue
        # For Azure the directory must match too. A subscription can be
        # moved between directories, so subscription equality alone does
        # not establish that the expected organization authenticated.
        if binding.directory_id is not None and binding.directory_id != actual.directory_id:
            continue
        return binding

    # The message names what was expected and what arrived. Both are
    # account identifiers, not secrets — an AWS account id appears in
    # every ARN, and a subscription id in every Azure resource id.
    permitted = ", ".join(sorted(b.account_id for b in candidates))
    raise CloudIdentityMismatch(
        f"authenticated {actual.provider.value} account {actual.account_id!r}"
        + (f" in directory {actual.directory_id!r}" if actual.directory_id else "")
        + f" is not bound to tenant {tenant_id!s} (permitted: {permitted})"
    )


__all__ = [
    "AuthenticatedCloudIdentity",
    "CloudAccountBinding",
    "verify_cloud_identity",
]
