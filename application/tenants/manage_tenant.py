"""``ManageTenant`` (blueprint §4).

The blueprint names this component but gives it no further
specification anywhere else in the document — no described fields,
lifecycle, or operations beyond the tree entry itself. Implementing a
speculative CRUD surface (update/deactivate/list) would mean inventing
behavior the blueprint doesn't define.

What *is* fully specified is the Domain's ``Tenant`` entity itself
(``domain.tenants.tenant``) — so this class implements only pure
delegation to it: registering a tenant is exactly constructing a
``Tenant`` and letting the Domain validate it. Nothing here adds new
business rules; all validation still lives in ``Tenant.__post_init__``.

Known limitation: anything beyond registration (lookup, update,
deactivation) is intentionally not implemented — see
docs/architecture/phase-2-application.md, Known Limitations.
"""

from __future__ import annotations

from domain.shared.identifiers import TenantId
from domain.tenants.tenant import Tenant


class ManageTenant:
    """Application-level entry point for tenant registration."""

    def register(self, *, tenant_id: str, name: str) -> Tenant:
        """Register a tenant. Raises ``InvalidTenant`` (a Domain
        exception) unchanged if the data is invalid — this method adds
        no validation of its own.
        """

        return Tenant(id=TenantId(tenant_id), name=name)
