"""``QueryFindings`` (blueprint §4).

Thin orchestration over ``FindingRepositoryPort``. Re-verifies tenant
scoping on the way out (defense in depth, blueprint's tenant-isolation
principle applied at every layer, not just the Domain) — an adapter that
returns cross-tenant data is treated as a violation, not silently
trusted.
"""

from __future__ import annotations

from application.findings.finding_repository import FindingRepositoryPort
from domain.findings.models import Finding
from domain.shared.identifiers import TenantId
from domain.tenants.isolation import ensure_same_tenant


class QueryFindings:
    """Application-level query for a tenant's findings."""

    def __init__(self, repository: FindingRepositoryPort) -> None:
        self._repository = repository

    def execute(self, *, tenant_id: TenantId) -> tuple[Finding, ...]:
        findings = self._repository.query(tenant_id)
        for finding in findings:
            ensure_same_tenant(tenant_id, finding.tenant_id, context="QueryFindings result")
        return findings
