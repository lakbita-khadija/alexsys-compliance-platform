"""PostgreSQL implementations of the scan-side ports (Phase 4).

Every method takes ``tenant_id`` and every WHERE clause includes it.
That is not belt-and-braces: it is the structural guarantee that makes
cross-tenant leakage impossible by construction rather than by review
(Part 16). A query here that forgot the tenant predicate would be a
security bug, so the predicate is never optional and never inferred.

Bulk writes use SQLAlchemy Core ``insert()`` with a list of dicts, which
psycopg3 sends as a single multi-row statement. A per-row ORM ``add()``
loop over a large account would issue one round trip per finding
(Part 15).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from application.ports.persistence.repositories import (
    AttackPathRepository,
    ComplianceSnapshot,
    FindingHistoryEntry,
    FindingSnapshotRepository,
    LogicalFindingRepository,
    ResourceSnapshotRepository,
    ScanHistoryQueryRepository,
    ScanRepository,
    SeverityBreakdown,
)
from domain.attack_paths.models import AttackPath
from domain.findings.models import Finding
from domain.resources.models import NormalizedResource
from domain.scans.lifecycle import LifecycleState, LogicalFinding
from domain.scans.models import Scan, ScanError, ScanStatus
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.persistence.postgres.mappers.mappers import (
    attack_path_row_to_summary,
    attack_path_to_row,
    finding_to_domain,
    finding_to_row,
    logical_finding_to_domain,
    logical_finding_to_row,
    resource_to_domain,
    resource_to_row,
    scan_error_to_domain,
    scan_error_to_row,
    scan_to_domain,
    scan_to_row,
)
from infrastructure.persistence.postgres.models.tables import (
    PostgresAttackPathModel,
    PostgresFindingSnapshotModel,
    PostgresLogicalFindingModel,
    PostgresResourceSnapshotModel,
    PostgresScanErrorModel,
    PostgresScanModel,
)

#: Rows per INSERT statement. Large enough that per-statement overhead is
#: amortized, small enough that one statement's parameter list stays well
#: inside PostgreSQL's 65535-parameter limit even for the widest table
#: (finding_snapshots, ~24 columns => ~24k parameters at 1000 rows).
BATCH_SIZE = 1000


def _batched(rows: list[dict[str, Any]], size: int = BATCH_SIZE):
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


class PostgresScanRepository(ScanRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, scan: Scan) -> None:
        # ON CONFLICT DO NOTHING makes scan creation idempotent: a
        # retried launch of the same deterministic scan_key must not
        # raise and must not duplicate (Part 14).
        stmt = pg_insert(PostgresScanModel).values(**scan_to_row(scan))
        self._session.execute(stmt.on_conflict_do_nothing(index_elements=["scan_key"]))

    def save(self, scan: Scan) -> None:
        row = scan_to_row(scan)
        stmt = pg_insert(PostgresScanModel).values(**row)
        updatable = {k: v for k, v in row.items() if k not in ("scan_key", "created_at")}
        self._session.execute(
            stmt.on_conflict_do_update(index_elements=["scan_key"], set_=updatable)
        )

    def update_status(self, *, tenant_id: TenantId, scan_key: str, status: ScanStatus) -> None:
        self._session.execute(
            update(PostgresScanModel)
            .where(
                PostgresScanModel.scan_key == scan_key,
                PostgresScanModel.tenant_id == str(tenant_id),
            )
            .values(status=status.value)
        )

    def get(self, *, tenant_id: TenantId, scan_key: str) -> Scan | None:
        row = self._session.execute(
            select(PostgresScanModel).where(
                PostgresScanModel.scan_key == scan_key,
                PostgresScanModel.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        errors = self._session.execute(
            select(PostgresScanErrorModel).where(
                PostgresScanErrorModel.scan_key == scan_key,
                PostgresScanErrorModel.tenant_id == str(tenant_id),
            )
        ).scalars().all()
        return scan_to_domain(row, errors=tuple(scan_error_to_domain(e) for e in errors))

    def list_recent(self, *, tenant_id: TenantId, limit: int = 50, offset: int = 0) -> tuple[Scan, ...]:
        rows = self._session.execute(
            select(PostgresScanModel)
            .where(PostgresScanModel.tenant_id == str(tenant_id))
            .order_by(PostgresScanModel.started_at.desc())
            .limit(limit)
            .offset(offset)
        ).scalars().all()
        return tuple(scan_to_domain(r) for r in rows)

    def record_errors(
        self, *, tenant_id: TenantId, scan_key: str, errors: Sequence[ScanError]
    ) -> None:
        if not errors:
            return
        # Replace rather than append, so re-persisting a scan does not
        # accumulate duplicate error rows.
        self._session.execute(
            delete(PostgresScanErrorModel).where(
                PostgresScanErrorModel.scan_key == scan_key,
                PostgresScanErrorModel.tenant_id == str(tenant_id),
            )
        )
        rows = [scan_error_to_row(e, tenant_id=tenant_id, scan_key=scan_key) for e in errors]
        self._session.execute(insert(PostgresScanErrorModel), rows)


class PostgresResourceSnapshotRepository(ResourceSnapshotRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_all(
        self, *, tenant_id: TenantId, scan_key: str, resources: Sequence[NormalizedResource]
    ) -> int:
        if not resources:
            return 0
        rows = [resource_to_row(r, tenant_id=tenant_id, scan_key=scan_key) for r in resources]
        written = 0
        for batch in _batched(rows):
            stmt = pg_insert(PostgresResourceSnapshotModel).values(batch)
            # Idempotent on (scan_key, resource_id): re-persisting a scan
            # updates the snapshot instead of duplicating it.
            self._session.execute(
                stmt.on_conflict_do_update(
                    constraint="uq_resource_snapshot_scan_resource",
                    set_={
                        "attributes": stmt.excluded.attributes,
                        "tags": stmt.excluded.tags,
                        "relationships": stmt.excluded.relationships,
                        "collected_at": stmt.excluded.collected_at,
                    },
                )
            )
            written += len(batch)
        return written

    def get_for_scan(self, *, tenant_id: TenantId, scan_key: str) -> tuple[NormalizedResource, ...]:
        rows = self._session.execute(
            select(PostgresResourceSnapshotModel).where(
                PostgresResourceSnapshotModel.tenant_id == str(tenant_id),
                PostgresResourceSnapshotModel.scan_key == scan_key,
            )
        ).scalars().all()
        return tuple(resource_to_domain(r) for r in rows)

    def get_resource_history(
        self, *, tenant_id: TenantId, resource_id: ResourceId, limit: int = 50
    ) -> tuple[tuple[str, NormalizedResource], ...]:
        rows = self._session.execute(
            select(PostgresResourceSnapshotModel)
            .where(
                PostgresResourceSnapshotModel.tenant_id == str(tenant_id),
                PostgresResourceSnapshotModel.resource_id == str(resource_id),
            )
            .order_by(PostgresResourceSnapshotModel.collected_at.desc())
            .limit(limit)
        ).scalars().all()
        return tuple((r.scan_key, resource_to_domain(r)) for r in rows)


class PostgresFindingSnapshotRepository(FindingSnapshotRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_all(self, *, tenant_id: TenantId, scan_key: str, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        rows = [finding_to_row(f, scan_key=scan_key) for f in findings]
        written = 0
        for batch in _batched(rows):
            stmt = pg_insert(PostgresFindingSnapshotModel).values(batch)
            self._session.execute(stmt.on_conflict_do_nothing(index_elements=["finding_id"]))
            written += len(batch)
        return written

    def get_for_scan(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        status: str | None = None,
        severity: Severity | None = None,
    ) -> tuple[Finding, ...]:
        query = select(PostgresFindingSnapshotModel).where(
            PostgresFindingSnapshotModel.tenant_id == str(tenant_id),
            PostgresFindingSnapshotModel.scan_key == scan_key,
        )
        if status is not None:
            query = query.where(PostgresFindingSnapshotModel.status == status)
        if severity is not None:
            query = query.where(PostgresFindingSnapshotModel.severity == severity.value)
        rows = self._session.execute(query).scalars().all()
        return tuple(finding_to_domain(r) for r in rows)

    def get_by_id(self, *, tenant_id: TenantId, finding_id: str) -> Finding | None:
        row = self._session.execute(
            select(PostgresFindingSnapshotModel).where(
                PostgresFindingSnapshotModel.tenant_id == str(tenant_id),
                PostgresFindingSnapshotModel.finding_id == finding_id,
            )
        ).scalar_one_or_none()
        return finding_to_domain(row) if row is not None else None

    def get_history(
        self, *, tenant_id: TenantId, logical_finding_id: str, limit: int = 100
    ) -> tuple[FindingHistoryEntry, ...]:
        rows = self._session.execute(
            select(
                PostgresFindingSnapshotModel.scan_key,
                PostgresFindingSnapshotModel.detected_at,
                PostgresFindingSnapshotModel.status,
                PostgresFindingSnapshotModel.severity,
                PostgresFindingSnapshotModel.finding_id,
            )
            .where(
                PostgresFindingSnapshotModel.tenant_id == str(tenant_id),
                PostgresFindingSnapshotModel.logical_finding_id == logical_finding_id,
            )
            .order_by(PostgresFindingSnapshotModel.detected_at.desc())
            .limit(limit)
        ).all()
        return tuple(
            FindingHistoryEntry(
                scan_key=r.scan_key,
                scanned_at=r.detected_at,
                status=r.status,
                severity=Severity(r.severity),
                finding_id=r.finding_id,
            )
            for r in rows
        )


class PostgresLogicalFindingRepository(LogicalFindingRepository):
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_active(self, *, tenant_id: TenantId) -> tuple[LogicalFinding, ...]:
        rows = self._session.execute(
            select(PostgresLogicalFindingModel).where(
                PostgresLogicalFindingModel.tenant_id == str(tenant_id),
                PostgresLogicalFindingModel.state.in_(
                    (LifecycleState.OPEN.value, LifecycleState.REOPENED.value)
                ),
            )
        ).scalars().all()
        return tuple(logical_finding_to_domain(r) for r in rows)

    def get_by_logical_ids(
        self, *, tenant_id: TenantId, logical_ids: Sequence[str]
    ) -> Mapping[str, LogicalFinding]:
        if not logical_ids:
            return {}
        rows = self._session.execute(
            select(PostgresLogicalFindingModel).where(
                PostgresLogicalFindingModel.tenant_id == str(tenant_id),
                PostgresLogicalFindingModel.logical_finding_id.in_(list(logical_ids)),
            )
        ).scalars().all()
        return {r.logical_finding_id: logical_finding_to_domain(r) for r in rows}

    def upsert_all(self, *, tenant_id: TenantId, logical_findings: Sequence[LogicalFinding]) -> int:
        if not logical_findings:
            return 0
        # Each LogicalFinding carries its own provider, because provider
        # is part of the lifecycle identity (see the
        # uq_logical_finding_identity constraint). No default is needed
        # or would be correct.
        rows = [logical_finding_to_row(lf) for lf in logical_findings]
        return self._upsert_rows(rows)

    def _upsert_rows(self, rows: list[dict[str, Any]]) -> int:
        written = 0
        for batch in _batched(rows):
            stmt = pg_insert(PostgresLogicalFindingModel).values(batch)
            self._session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["logical_finding_id"],
                    set_={
                        "state": stmt.excluded.state,
                        "severity": stmt.excluded.severity,
                        "last_seen_at": stmt.excluded.last_seen_at,
                        "last_seen_scan_key": stmt.excluded.last_seen_scan_key,
                        "resolved_at": stmt.excluded.resolved_at,
                        "resolved_scan_key": stmt.excluded.resolved_scan_key,
                        "reopen_count": stmt.excluded.reopen_count,
                        "occurrence_count": stmt.excluded.occurrence_count,
                        "suppressed_reason": stmt.excluded.suppressed_reason,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
            )
            written += len(batch)
        return written

    def get_by_state(
        self, *, tenant_id: TenantId, state: LifecycleState, limit: int = 100
    ) -> tuple[LogicalFinding, ...]:
        rows = self._session.execute(
            select(PostgresLogicalFindingModel)
            .where(
                PostgresLogicalFindingModel.tenant_id == str(tenant_id),
                PostgresLogicalFindingModel.state == state.value,
            )
            .order_by(PostgresLogicalFindingModel.last_seen_at.desc())
            .limit(limit)
        ).scalars().all()
        return tuple(logical_finding_to_domain(r) for r in rows)


class PostgresScanHistoryQueryRepository(ScanHistoryQueryRepository):
    """Read-only analytics. Every query is index-served — see the index
    definitions in models/tables.py for which index covers which.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _to_snapshot(row: Any) -> ComplianceSnapshot:
        return ComplianceSnapshot(
            scan_key=row.scan_key,
            tenant_id=TenantId(row.tenant_id),
            provider=CloudProvider(row.provider),
            account_id=row.account_id,
            scanned_at=row.started_at,
            status=ScanStatus(row.status),
            resource_count=row.resource_count,
            finding_count=row.finding_count,
            pass_count=row.pass_count,
            fail_count=row.fail_count,
            indeterminate_count=row.indeterminate_count,
            critical_count=row.critical_count,
            high_count=row.high_count,
            medium_count=row.medium_count,
            low_count=row.low_count,
        )

    def get_compliance_snapshot(
        self, *, tenant_id: TenantId, scan_key: str
    ) -> ComplianceSnapshot | None:
        row = self._session.execute(
            select(PostgresScanModel).where(
                PostgresScanModel.tenant_id == str(tenant_id),
                PostgresScanModel.scan_key == scan_key,
            )
        ).scalar_one_or_none()
        return self._to_snapshot(row) if row is not None else None

    def get_compliance_history(
        self,
        *,
        tenant_id: TenantId,
        provider: CloudProvider | None = None,
        account_id: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> tuple[ComplianceSnapshot, ...]:
        query = select(PostgresScanModel).where(PostgresScanModel.tenant_id == str(tenant_id))
        if provider is not None:
            query = query.where(PostgresScanModel.provider == provider.value)
        if account_id is not None:
            query = query.where(PostgresScanModel.account_id == account_id)
        if since is not None:
            query = query.where(PostgresScanModel.started_at >= since)
        rows = self._session.execute(
            query.order_by(PostgresScanModel.started_at.desc()).limit(limit)
        ).scalars().all()
        return tuple(self._to_snapshot(r) for r in rows)

    def count_findings_by(
        self, *, tenant_id: TenantId, scan_key: str, dimension: str
    ) -> tuple[SeverityBreakdown, ...]:
        columns = {
            "severity": PostgresFindingSnapshotModel.severity,
            "domain": PostgresFindingSnapshotModel.domain,
            "rule_id": PostgresFindingSnapshotModel.rule_id,
            "framework": PostgresFindingSnapshotModel.framework,
        }
        if dimension not in columns:
            raise ValueError(
                f"unsupported dimension {dimension!r}; expected one of {sorted(columns)}"
            )
        column = columns[dimension]
        rows = self._session.execute(
            select(column, func.count())
            .where(
                PostgresFindingSnapshotModel.tenant_id == str(tenant_id),
                PostgresFindingSnapshotModel.scan_key == scan_key,
                # FAILING findings only — counting passes here would
                # report a compliant account as full of criticals.
                PostgresFindingSnapshotModel.status == "fail",
            )
            .group_by(column)
            .order_by(func.count().desc())
        ).all()
        return tuple(
            SeverityBreakdown(dimension=dimension, value=str(value), count=count)
            for value, count in rows
        )

    def get_rule_regressions(
        self, *, tenant_id: TenantId, limit: int = 50
    ) -> tuple[LogicalFinding, ...]:
        rows = self._session.execute(
            select(PostgresLogicalFindingModel)
            .where(
                PostgresLogicalFindingModel.tenant_id == str(tenant_id),
                PostgresLogicalFindingModel.reopen_count > 0,
            )
            .order_by(PostgresLogicalFindingModel.last_seen_at.desc())
            .limit(limit)
        ).scalars().all()
        return tuple(logical_finding_to_domain(r) for r in rows)


class PostgresAttackPathRepository(AttackPathRepository):
    """Attack path persistence (STEP 4)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save_all(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        attack_paths: Sequence[AttackPath],
        created_at: datetime,
    ) -> int:
        if not attack_paths:
            return 0
        rows = [
            attack_path_to_row(p, scan_key=scan_key, created_at=created_at)
            for p in attack_paths
        ]
        written = 0
        for batch in _batched(rows):
            stmt = pg_insert(PostgresAttackPathModel).values(batch)
            # Idempotent: path ids are deterministic composites, so a
            # conflict means "we already recorded this exact path in this
            # exact scan". Re-persisting a scan must not duplicate rows
            # or fail.
            self._session.execute(
                stmt.on_conflict_do_nothing(index_elements=["attack_path_id", "scan_key"])
            )
            written += len(batch)
        return written

    def get_for_scan(self, *, tenant_id: TenantId, scan_key: str) -> tuple[dict, ...]:
        rows = (
            self._session.execute(
                select(PostgresAttackPathModel)
                .where(
                    PostgresAttackPathModel.tenant_id == str(tenant_id),
                    PostgresAttackPathModel.scan_key == scan_key,
                )
                # Highest risk first, then id — the same order the
                # analyzer produces, so the API and a fresh scan agree.
                .order_by(
                    PostgresAttackPathModel.risk_score.desc(),
                    PostgresAttackPathModel.attack_path_id.asc(),
                )
            )
            .scalars()
            .all()
        )
        return tuple(attack_path_row_to_summary(r) for r in rows)

    def get_by_id(self, *, tenant_id: TenantId, attack_path_id: str) -> dict | None:
        row = (
            self._session.execute(
                select(PostgresAttackPathModel).where(
                    # tenant_id FIRST and always: a path id alone must
                    # never be enough to read another tenant's data.
                    PostgresAttackPathModel.tenant_id == str(tenant_id),
                    PostgresAttackPathModel.attack_path_id == attack_path_id,
                )
            )
            .scalars()
            .first()
        )
        return attack_path_row_to_summary(row) if row is not None else None
