"""Reading persisted attack paths (STEP 5).

Attack paths are read back as **plain mappings**, not rebuilt into
`AttackPath` aggregates. The aggregate's invariants — path integrity,
tenant match on every node, blocked-implies-score-zero — are
construction-time guarantees over live `GraphNode`/`GraphEdge` objects.
Reconstituting them from JSONB would either re-validate against a graph
that no longer exists, or force the invariants to be relaxed. An
aggregate relaxed so it can be read back has stopped meaning anything.

The persisted row already carries everything a reader needs: the ordered
chain, the evidence, the score breakdown, the contributing findings.
"""

from __future__ import annotations

from typing import Sequence

from application.ports.auth import AuthenticatedIdentity, Role
from application.ports.persistence.repositories import AttackPathRepository


def _filtered(
    paths: Sequence[dict],
    *,
    severity: str | None,
    scenario: str | None,
    min_confidence: str | None,
) -> tuple[dict, ...]:
    """Apply the API's filters.

    Filtering here rather than in SQL keeps one implementation for both
    the scan-scoped and tenant-scoped reads. Page sizes are bounded by
    `PageRequest` (max 100), so the cost is trivial and the alternative —
    two divergent filter implementations — is not.
    """

    order = ("unknown", "low", "medium", "high")
    result = list(paths)
    if severity:
        result = [p for p in result if p["severity"] == severity]
    if scenario:
        result = [p for p in result if p["scenario"] == scenario]
    if min_confidence:
        floor = order.index(min_confidence)
        result = [
            p for p in result if order.index(p.get("confidence", "unknown")) >= floor
        ]
    return tuple(result)


class QueryAttackPathsForScan:
    """``GET /api/v1/scans/{scan_id}/attack-paths``."""

    def __init__(self, repository: AttackPathRepository) -> None:
        self._repository = repository

    def execute(
        self,
        *,
        identity: AuthenticatedIdentity,
        scan_key: str,
        severity: str | None = None,
        scenario: str | None = None,
        min_confidence: str | None = None,
    ) -> tuple[dict, ...]:
        identity.require_role(Role.READER)
        paths = self._repository.get_for_scan(
            # The security boundary, taken from the verified token —
            # never a parameter a caller can supply.
            tenant_id=identity.tenant_id,
            scan_key=scan_key,
        )
        return _filtered(
            paths, severity=severity, scenario=scenario, min_confidence=min_confidence
        )


class GetAttackPath:
    """``GET /api/v1/attack-paths/{id}`` — one path, tenant-scoped."""

    def __init__(self, repository: AttackPathRepository) -> None:
        self._repository = repository

    def execute(
        self, *, identity: AuthenticatedIdentity, attack_path_id: str
    ) -> dict | None:
        identity.require_role(Role.READER)
        return self._repository.get_by_id(
            tenant_id=identity.tenant_id, attack_path_id=attack_path_id
        )


__all__ = ["GetAttackPath", "QueryAttackPathsForScan"]
