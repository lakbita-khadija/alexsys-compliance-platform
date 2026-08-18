"""PostgreSQL adapters for the Phase 5 read/write ports.

The rule that shapes every method here: **filter, count and paginate in
the database**. Loading a tenant's findings into Python and slicing the
list satisfies the port's signature and defeats its purpose — a large
tenant would move hundreds of megabytes per page request (§34).

So each ``search`` builds one filtered statement, runs
``SELECT count(*)`` over it, then applies ``ORDER BY … LIMIT … OFFSET``.
Two round trips, both index-served, regardless of tenant size.

Filters reach here as typed dataclasses that the application layer
already validated, and every predicate is built with SQLAlchemy bound
parameters. No caller string is ever concatenated into SQL.
"""

from __future__ import annotations

from typing import Any, Sequence

from sqlalchemy import Select, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

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
from domain.audit.models import AuditAction, AuditActor, AuditEvent
from domain.compliance.scoring import (
    ComplianceScore,
    ScoreCounts,
    ScoreScope,
)
from domain.findings.models import Finding
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import TenantId
from infrastructure.persistence.postgres.mappers.mappers import finding_to_domain
from infrastructure.persistence.postgres.mappers.redaction import redact
from infrastructure.persistence.postgres.models.tables import (
    PostgresAuditEventModel,
    PostgresComplianceScoreModel,
    PostgresFindingSnapshotModel,
    PostgresLogicalFindingModel,
)

#: Severity ordering for SEVERITY_DESC. Expressed as a CASE rather than
#: relying on the stored text: alphabetically "high" < "low" < "medium",
#: which would sort MEDIUM above HIGH — a subtly wrong dashboard that no
#: type checker would catch.
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _severity_rank_case():
    from sqlalchemy import case

    return case(_SEVERITY_ORDER, value=PostgresFindingSnapshotModel.severity, else_=99)


class PostgresFindingQueryRepository(FindingQueryRepository):
    """Paged, filtered finding reads."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _base(self, tenant_id: TenantId, filters: FindingFilter) -> Select:
        model = PostgresFindingSnapshotModel
        # Tenant first, and never optional. Every other predicate is
        # additive on top of an already tenant-scoped set.
        stmt = select(model).where(model.tenant_id == str(tenant_id))

        if filters.framework is not None:
            stmt = stmt.where(model.framework == filters.framework)
        if filters.severity is not None:
            stmt = stmt.where(model.severity == filters.severity.value)
        if filters.status is not None:
            stmt = stmt.where(model.status == filters.status.value)
        if filters.domain is not None:
            stmt = stmt.where(model.domain == filters.domain)
        if filters.resource_id is not None:
            stmt = stmt.where(model.resource_id == filters.resource_id)
        if filters.rule_id is not None:
            stmt = stmt.where(model.rule_id == filters.rule_id)
        if filters.scan_key is not None:
            stmt = stmt.where(model.scan_key == filters.scan_key)
        if filters.account_id is not None:
            stmt = stmt.where(model.account_id == filters.account_id)
        if filters.detected_after is not None:
            stmt = stmt.where(model.detected_at >= filters.detected_after)
        if filters.detected_before is not None:
            stmt = stmt.where(model.detected_at <= filters.detected_before)

        if filters.provider is not None or filters.lifecycle_state is not None:
            # Provider and lifecycle live on logical_findings, not on the
            # snapshot. Joined only when actually filtered on, so the
            # common query stays a single-table index scan.
            stmt = stmt.join(
                PostgresLogicalFindingModel,
                (
                    PostgresLogicalFindingModel.logical_finding_id
                    == model.logical_finding_id
                )
                & (PostgresLogicalFindingModel.tenant_id == model.tenant_id),
            )
            if filters.provider is not None:
                stmt = stmt.where(
                    PostgresLogicalFindingModel.provider == filters.provider.value
                )
            if filters.lifecycle_state is not None:
                stmt = stmt.where(
                    PostgresLogicalFindingModel.state == filters.lifecycle_state.value
                )

        return stmt

    def search(
        self,
        *,
        tenant_id: TenantId,
        filters: FindingFilter,
        page: PageRequest,
        sort: SortOrder = SortOrder.DETECTED_AT_DESC,
    ) -> Page[Finding]:
        model = PostgresFindingSnapshotModel
        stmt = self._base(tenant_id, filters)

        # Counted in the database over the same predicate — never
        # len(list(rows)).
        total = self._session.execute(
            select(func.count()).select_from(stmt.subquery())
        ).scalar_one()

        # Every ordering ends with the primary key. Without that unique
        # tiebreaker, rows sharing a timestamp can reorder between
        # queries and a row can appear on two pages or none.
        if sort is SortOrder.DETECTED_AT_ASC:
            stmt = stmt.order_by(model.detected_at.asc(), model.finding_id.asc())
        elif sort is SortOrder.SEVERITY_DESC:
            stmt = stmt.order_by(_severity_rank_case().asc(), model.finding_id.asc())
        else:
            stmt = stmt.order_by(model.detected_at.desc(), model.finding_id.asc())

        rows = self._session.execute(stmt.limit(page.limit).offset(page.offset)).scalars().all()
        return Page(
            items=tuple(finding_to_domain(row) for row in rows),
            total=total,
            limit=page.limit,
            offset=page.offset,
        )

    def get(self, *, tenant_id: TenantId, finding_id: str) -> Finding | None:
        model = PostgresFindingSnapshotModel
        row = self._session.execute(
            select(model).where(
                model.finding_id == finding_id,
                # Redundant while finding_id is globally unique, and
                # present so the pattern is uniform and a missing tenant
                # filter is visible in review.
                model.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return finding_to_domain(row) if row is not None else None


class PostgresComplianceScoreRepository(ComplianceScoreRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_all(self, *, tenant_id: TenantId, scores: Sequence[ComplianceScore]) -> int:
        if not scores:
            return 0

        rows: list[dict[str, Any]] = []
        for score in scores:
            if score.tenant_id != tenant_id:
                raise TenantIsolationViolation(
                    "refusing to persist a score belonging to another tenant"
                )
            rows.append(
                {
                    "tenant_id": str(score.tenant_id),
                    "scope": score.scope.value,
                    "scope_value": score.scope_value,
                    "scan_key": score.scan_key,
                    "passed": score.counts.passed,
                    "failed": score.counts.failed,
                    "indeterminate": score.counts.indeterminate,
                    "critical": score.counts.critical,
                    "high": score.counts.high,
                    "medium": score.counts.medium,
                    "low": score.counts.low,
                    "computed_at": score.computed_at,
                }
            )

        statement = pg_insert(PostgresComplianceScoreModel).values(rows)
        # Upsert on identity so re-scoring a scan (a retry, a redelivered
        # job) replaces rather than duplicates.
        statement = statement.on_conflict_do_update(
            index_elements=["tenant_id", "scope", "scope_value", "scan_key"],
            set_={
                column: statement.excluded[column]
                for column in (
                    "passed",
                    "failed",
                    "indeterminate",
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "computed_at",
                )
            },
        )
        self._session.execute(statement)
        return len(rows)

    @staticmethod
    def _to_domain(row: Any) -> ComplianceScore:
        return ComplianceScore(
            tenant_id=TenantId(row.tenant_id),
            scope=ScoreScope(row.scope),
            scope_value=row.scope_value,
            counts=ScoreCounts(
                passed=row.passed,
                failed=row.failed,
                indeterminate=row.indeterminate,
                critical=row.critical,
                high=row.high,
                medium=row.medium,
                low=row.low,
            ),
            computed_at=row.computed_at,
            scan_key=row.scan_key,
        )

    def search(
        self, *, tenant_id: TenantId, filters: ScoreFilter, page: PageRequest
    ) -> Page[ComplianceScore]:
        model = PostgresComplianceScoreModel
        stmt = select(model).where(model.tenant_id == str(tenant_id))

        if filters.scope is not None:
            stmt = stmt.where(model.scope == filters.scope.value)
        if filters.scope_value is not None:
            stmt = stmt.where(model.scope_value == filters.scope_value)
        if filters.scan_key is not None:
            stmt = stmt.where(model.scan_key == filters.scan_key)
        if filters.computed_after is not None:
            stmt = stmt.where(model.computed_at >= filters.computed_after)
        if filters.computed_before is not None:
            stmt = stmt.where(model.computed_at <= filters.computed_before)

        total = self._session.execute(
            select(func.count()).select_from(stmt.subquery())
        ).scalar_one()

        stmt = stmt.order_by(model.computed_at.desc(), model.id.asc())
        rows = self._session.execute(stmt.limit(page.limit).offset(page.offset)).scalars().all()
        return Page(
            items=tuple(self._to_domain(row) for row in rows),
            total=total,
            limit=page.limit,
            offset=page.offset,
        )

    def latest(
        self, *, tenant_id: TenantId, scope: ScoreScope, scope_value: str | None = None
    ) -> ComplianceScore | None:
        model = PostgresComplianceScoreModel
        stmt = (
            select(model)
            .where(model.tenant_id == str(tenant_id), model.scope == scope.value)
            .order_by(model.computed_at.desc(), model.id.desc())
            .limit(1)
        )
        # `IS NULL` rather than `= NULL`: the tenant-scope row has a NULL
        # scope_value, and `= NULL` is never true in SQL, so the headline
        # tenant score would silently never be found.
        stmt = stmt.where(
            model.scope_value.is_(None)
            if scope_value is None
            else model.scope_value == scope_value
        )

        row = self._session.execute(stmt).scalar_one_or_none()
        return self._to_domain(row) if row is not None else None


class PostgresAuditEventRepository(AuditEventRepository):
    """Append-only. No update path, no delete path — deliberately."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, event: AuditEvent) -> None:
        self._session.execute(
            pg_insert(PostgresAuditEventModel)
            .values(
                event_id=event.event_id,
                tenant_id=str(event.tenant_id),
                actor_subject=event.actor.subject,
                actor_kind=event.actor.kind,
                action=event.action.value,
                resource=event.resource,
                resource_type=event.resource_type,
                occurred_at=event.occurred_at,
                correlation_id=event.correlation_id,
                # NOTE the attribute name: the COLUMN is called
                # "metadata", but passing `metadata=` here would resolve
                # to SQLAlchemy's own declarative `MetaData` object
                # instead of the column, which fails deep inside the ORM
                # with an unrelated-looking AttributeError. The mapped
                # attribute is `event_metadata` precisely to avoid that
                # collision, and it is what must be used here.
                #
                # The domain already refuses credential-shaped keys;
                # redacting again is defense in depth, matching how
                # finding evidence is handled.
                event_metadata=redact(dict(event.metadata)),
            )
            # Recording the same event twice (a retried job) is a no-op
            # rather than an integrity error that would fail the
            # operation being audited.
            .on_conflict_do_nothing(index_elements=["event_id"])
        )

    def search(self, *, tenant_id: TenantId, page: PageRequest) -> Page[AuditEvent]:
        model = PostgresAuditEventModel
        stmt = select(model).where(model.tenant_id == str(tenant_id))

        total = self._session.execute(
            select(func.count()).select_from(stmt.subquery())
        ).scalar_one()

        stmt = stmt.order_by(model.occurred_at.desc(), model.event_id.asc())
        rows = self._session.execute(stmt.limit(page.limit).offset(page.offset)).scalars().all()

        return Page(
            items=tuple(
                AuditEvent(
                    event_id=row.event_id,
                    tenant_id=TenantId(row.tenant_id),
                    actor=AuditActor(subject=row.actor_subject, kind=row.actor_kind),
                    action=AuditAction(row.action),
                    occurred_at=row.occurred_at,
                    resource=row.resource,
                    resource_type=row.resource_type,
                    correlation_id=row.correlation_id,
                    metadata=dict(row.event_metadata or {}),
                )
                for row in rows
            ),
            total=total,
            limit=page.limit,
            offset=page.offset,
        )
