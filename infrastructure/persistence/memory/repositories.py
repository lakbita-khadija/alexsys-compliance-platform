"""In-memory repository adapters (Phase 5).

Two real jobs, neither of them "a shortcut so tests pass":

1. **The core-stub** §14 asks for. The AI engineer needs
   ``CIQ_CORE_API_BASE_URL=http://core-stub:9000`` to serve realistic
   data without PostgreSQL, cloud credentials, or our whole deployment.
   Running the real FastAPI app over these repositories gives them the
   real routing, real auth, real error envelope and real schemas.

2. **Fast API-layer tests.** Routing, authentication, tenant scoping,
   pagination and error handling are logic worth testing in
   milliseconds. Whether PostgreSQL honours the same semantics is a
   separate question answered by the real-database suite — these do not
   replace it, and the Postgres repositories are tested against a real
   server exactly as Phase 4's are.

Tenant scoping is implemented here as strictly as in SQL: every method
filters on ``tenant_id``, and ``get`` returns ``None`` for another
tenant's row rather than raising. If these were laxer than the database,
a cross-tenant test could pass here and fail in production.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Iterable, Sequence

from application.ports.persistence.repositories import AttackPathRepository
from application.ports.queries import (
    AuditEventRepository,
    ComplianceScoreRepository,
    FindingFilter,
    FindingQueryRepository,
    Page,
    PageRequest,
    ScoreFilter,
    SortOrder,
)
from domain.attack_paths.models import AttackPath
from domain.audit.models import AuditEvent
from domain.compliance.scoring import ComplianceScore, ScoreScope
from domain.findings.models import Finding
from domain.shared.enums import Severity
from domain.shared.identifiers import TenantId

#: Severity ordering for SEVERITY_DESC. Explicit because the enum is
#: alphabetical by value ("critical" < "high" < "low" < "medium"), which
#: would sort MEDIUM above HIGH — a subtly wrong dashboard.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _paginate(items: list, page: PageRequest) -> tuple[tuple, int]:
    total = len(items)
    window = items[page.offset : page.offset + page.limit]
    return tuple(window), total


class InMemoryFindingQueryRepository(FindingQueryRepository):
    """Findings in a dict, filtered and sorted like the SQL adapter."""

    def __init__(self, findings: Iterable[Finding] = ()) -> None:
        self._findings: list[Finding] = list(findings)
        self._lock = threading.RLock()

    def add(self, *findings: Finding) -> None:
        with self._lock:
            self._findings.extend(findings)

    def _matches(self, finding: Finding, filters: FindingFilter) -> bool:
        if filters.framework is not None and finding.framework != filters.framework:
            return False
        if filters.severity is not None and finding.severity is not filters.severity:
            return False
        if filters.status is not None and finding.status is not filters.status:
            return False
        if filters.domain is not None and finding.domain != filters.domain:
            return False
        if filters.resource_id is not None and str(finding.resource_id) != filters.resource_id:
            return False
        if filters.rule_id is not None and str(finding.rule_id) != filters.rule_id:
            return False
        if filters.scan_key is not None and finding.scan_id != filters.scan_key:
            return False
        if filters.account_id is not None and finding.account_id != filters.account_id:
            return False
        if filters.detected_after is not None and finding.detected_at < filters.detected_after:
            return False
        if filters.detected_before is not None and finding.detected_at > filters.detected_before:
            return False
        return True

    def search(
        self,
        *,
        tenant_id: TenantId,
        filters: FindingFilter,
        page: PageRequest,
        sort: SortOrder = SortOrder.DETECTED_AT_DESC,
    ) -> Page[Finding]:
        with self._lock:
            # Tenant first, always. Never a filter among filters.
            matched = [
                f
                for f in self._findings
                if f.tenant_id == tenant_id and self._matches(f, filters)
            ]

        # Every ordering ends with `id` so pagination is stable: without a
        # unique tiebreaker, equal timestamps can reorder between calls
        # and a row can appear on two pages or none.
        if sort is SortOrder.DETECTED_AT_ASC:
            matched.sort(key=lambda f: (f.detected_at, str(f.id)))
        elif sort is SortOrder.SEVERITY_DESC:
            matched.sort(key=lambda f: (_SEVERITY_RANK[f.severity], str(f.id)))
        else:
            matched.sort(key=lambda f: (f.detected_at, str(f.id)), reverse=True)

        items, total = _paginate(matched, page)
        return Page(items=items, total=total, limit=page.limit, offset=page.offset)

    def get(self, *, tenant_id: TenantId, finding_id: str) -> Finding | None:
        with self._lock:
            for finding in self._findings:
                if str(finding.id) == finding_id and finding.tenant_id == tenant_id:
                    return finding
        # Deliberately identical for "absent" and "another tenant's".
        return None


class InMemoryComplianceScoreRepository(ComplianceScoreRepository):
    def __init__(self) -> None:
        self._scores: list[ComplianceScore] = []
        self._lock = threading.RLock()

    @staticmethod
    def _identity(score: ComplianceScore) -> tuple:
        return (
            str(score.tenant_id),
            score.scope.value,
            score.scope_value,
            score.scan_key,
        )

    def save_all(self, *, tenant_id: TenantId, scores) -> int:
        with self._lock:
            for score in scores:
                if score.tenant_id != tenant_id:
                    from domain.shared.errors import TenantIsolationViolation

                    raise TenantIsolationViolation(
                        "refusing to persist a score belonging to another tenant"
                    )
                identity = self._identity(score)
                # Replace-by-identity mirrors the SQL adapter's upsert, so
                # recomputing a scan's scores is idempotent in both.
                self._scores = [s for s in self._scores if self._identity(s) != identity]
                self._scores.append(score)
            return len(list(scores))

    def search(
        self, *, tenant_id: TenantId, filters: ScoreFilter, page: PageRequest
    ) -> Page[ComplianceScore]:
        with self._lock:
            matched = [s for s in self._scores if s.tenant_id == tenant_id]

        if filters.scope is not None:
            matched = [s for s in matched if s.scope is filters.scope]
        if filters.scope_value is not None:
            matched = [s for s in matched if s.scope_value == filters.scope_value]
        if filters.scan_key is not None:
            matched = [s for s in matched if s.scan_key == filters.scan_key]
        if filters.computed_after is not None:
            matched = [s for s in matched if s.computed_at >= filters.computed_after]
        if filters.computed_before is not None:
            matched = [s for s in matched if s.computed_at <= filters.computed_before]

        matched.sort(
            key=lambda s: (s.computed_at, s.scope.value, s.scope_value or ""), reverse=True
        )
        items, total = _paginate(matched, page)
        return Page(items=items, total=total, limit=page.limit, offset=page.offset)

    def latest(
        self, *, tenant_id: TenantId, scope: ScoreScope, scope_value: str | None = None
    ) -> ComplianceScore | None:
        with self._lock:
            candidates = [
                s
                for s in self._scores
                if s.tenant_id == tenant_id
                and s.scope is scope
                and s.scope_value == scope_value
            ]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.computed_at)


class InMemoryAuditEventRepository(AuditEventRepository):
    """Append-only, like the real one: no update, no delete."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.RLock()

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def search(self, *, tenant_id: TenantId, page: PageRequest) -> Page[AuditEvent]:
        with self._lock:
            matched = [e for e in self._events if e.tenant_id == tenant_id]
        matched.sort(key=lambda e: (e.occurred_at, e.event_id), reverse=True)
        items, total = _paginate(matched, page)
        return Page(items=items, total=total, limit=page.limit, offset=page.offset)

    @property
    def all_events(self) -> tuple[AuditEvent, ...]:
        """Every event across every tenant — for tests only.

        Deliberately not on the port: no production caller should be
        able to read across tenants.
        """

        with self._lock:
            return tuple(self._events)


class InMemoryAttackPathRepository(AttackPathRepository):
    """In-memory attack paths for the stub app (STEP 5).

    Stores the same plain mappings the Postgres repository returns, so
    the API layer cannot tell the two apart — which is the point of a
    stub: it exercises the real router and the real schemas.
    """

    def __init__(self) -> None:
        self._rows: list[dict] = []

    def add(self, row: dict) -> None:
        self._rows.append(row)

    def save_all(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        attack_paths: Sequence[AttackPath],
        created_at: datetime,
    ) -> int:
        """Not supported here — and it says so rather than returning 0.

        The stub app has no collector and therefore never runs a scan,
        so this is unreachable in the two contexts this adapter serves.
        Writing paths would require the domain→row mapping, which lives
        with the Postgres adapter that owns the storage shape. A silent
        ``return 0`` would make a future caller's dropped write look like
        an empty result set.
        """

        raise NotImplementedError(
            "the in-memory attack path repository is read-only; "
            "use PostgresAttackPathRepository to persist a scan"
        )

    def get_for_scan(self, *, tenant_id: TenantId, scan_key: str) -> tuple[dict, ...]:
        rows = [
            r
            for r in self._rows
            if r["tenant_id"] == str(tenant_id) and r["scan_key"] == scan_key
        ]
        # Same order the Postgres repository and the analyzer produce.
        return tuple(sorted(rows, key=lambda r: (-r["risk_score"], r["id"])))

    def get_by_id(self, *, tenant_id: TenantId, attack_path_id: str) -> dict | None:
        return next(
            (
                r
                for r in self._rows
                # tenant FIRST: an id alone must never reach another
                # tenant's path.
                if r["tenant_id"] == str(tenant_id) and r["id"] == attack_path_id
            ),
            None,
        )
