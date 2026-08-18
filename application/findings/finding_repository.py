"""``FindingRepositoryPort`` — the port behind ``QueryFindings`` (blueprint
§4). Concrete persistence is explicitly ``infrastructure/persistence/
[FUTURE]`` (blueprint §5) — not implemented here, only the abstraction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from domain.findings.models import Finding
from domain.shared.identifiers import TenantId


class FindingRepositoryPort(ABC):
    """Port: read access to persisted ``Finding``s."""

    @abstractmethod
    def query(self, tenant_id: TenantId) -> tuple[Finding, ...]:
        """Return every ``Finding`` belonging to ``tenant_id``."""
