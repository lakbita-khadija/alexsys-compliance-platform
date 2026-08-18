"""Ports for cloud identity verification (STEP 6.5).

Two ports, because the two questions have different answers and
different owners:

* :class:`CloudIdentityProvider` — *who did we authenticate as?* Answered
  by the cloud provider, over the network, by an infrastructure adapter
  (`sts:GetCallerIdentity`, an Entra token's `tid` claim).
* :class:`CloudAccountDirectory` — *which accounts may this tenant
  scan?* Answered by ComplianceIQ's own configuration.

Keeping them apart is what makes the gate meaningful. If one component
supplied both sides of the comparison, it would be comparing
configuration against itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from domain.shared.enums import CloudProvider
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import AuthenticatedCloudIdentity, CloudAccountBinding


class CloudIdentityProvider(ABC):
    """Port: ask the cloud provider who we are.

    Implementations must make a real call. Returning configuration —
    "the subscription id we were handed" — would satisfy the type and
    defeat the purpose; that mistake is exactly what
    `cloud-auth-readiness.md` §3.3 documents in the pre-STEP-6.5 Azure
    collector.

    A failure to determine identity must **raise**, never return a
    partial or guessed value. "We could not tell which account this is"
    is not a licence to proceed.
    """

    @abstractmethod
    def authenticated_identity(self) -> AuthenticatedCloudIdentity:
        """Return the provider's own statement of who this session is."""


class CloudAccountDirectory(ABC):
    """Port: which cloud accounts a tenant is permitted to scan."""

    @abstractmethod
    def bindings_for(
        self, *, tenant_id: TenantId, provider: CloudProvider
    ) -> tuple[CloudAccountBinding, ...]:
        """Return this tenant's bindings. Empty means *nothing permitted*."""


__all__ = ["CloudAccountDirectory", "CloudIdentityProvider"]
