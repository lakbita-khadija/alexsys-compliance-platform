"""Paged finding queries for the API (Phase 5, §5).

Separate from the existing ``QueryFindings`` (which returns every finding
for a tenant via ``FindingRepositoryPort``) rather than replacing it:
that use case and its port are Phase 2 contracts with their own tests,
and breaking them to add pagination would violate the brief's
"preserve backward compatibility". These are new use cases against a new
port, and the two coexist.

Both use cases here are thin on purpose. They exist to enforce exactly
one thing the routers must not be trusted to remember:

    the tenant comes from the verified identity, never from the request.

The router hands over an ``AuthenticatedIdentity``; the tenant is read
off it here. There is no parameter through which a caller could supply a
different tenant, so the isolation rule cannot be bypassed by a future
route handler that forgets it.
"""

from __future__ import annotations

from application.ports.auth import AuthenticatedIdentity, Role
from application.ports.queries import (
    FindingFilter,
    FindingQueryRepository,
    Page,
    PageRequest,
    SortOrder,
)
from domain.findings.models import Finding


class QueryFindingsPage:
    """``GET /api/v1/findings`` — one page of a tenant's findings."""

    def __init__(self, repository: FindingQueryRepository) -> None:
        self._repository = repository

    def execute(
        self,
        *,
        identity: AuthenticatedIdentity,
        filters: FindingFilter | None = None,
        page: PageRequest | None = None,
        sort: SortOrder = SortOrder.DETECTED_AT_DESC,
    ) -> Page[Finding]:
        identity.require_role(Role.READER)
        return self._repository.search(
            # The security boundary. Not a parameter of this method.
            tenant_id=identity.tenant_id,
            filters=filters or FindingFilter(),
            page=page or PageRequest(),
            sort=sort,
        )


class GetFinding:
    """``GET /api/v1/findings/{id}`` — one finding, tenant-scoped."""

    def __init__(self, repository: FindingQueryRepository) -> None:
        self._repository = repository

    def execute(self, *, identity: AuthenticatedIdentity, finding_id: str) -> Finding | None:
        """Return the finding, or ``None``.

        ``None`` covers both "no such finding" and "exists, but belongs
        to another tenant", and the caller cannot tell which. That is
        the point (§12): a distinguishable response would let a caller
        enumerate the existence of other tenants' findings by probing
        ids, which is an information leak even when the data itself is
        never returned.
        """

        identity.require_role(Role.READER)
        return self._repository.get(tenant_id=identity.tenant_id, finding_id=finding_id)
