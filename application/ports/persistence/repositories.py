"""Persistence PORTS (Phase 4, Part 13).

Abstract interfaces the Application layer depends on. Concrete
PostgreSQL implementations live in
``infrastructure/persistence/postgres/repositories/`` and are injected;
nothing in this module knows that PostgreSQL exists.

Design rules applied here:

* **Ports are shaped by use cases, not by tables.** There is no
  ``ScanTargetRepository`` even though ``scan_targets`` is a table —
  nothing ever needs one independently of its scan. Conversely
  ``ScanHistoryQueryRepository`` spans several tables because that is
  what a dashboard actually asks for.
* **Every method takes ``tenant_id`` explicitly.** It is never inferred
  from ambient state, and never optional. A repository method that
  cannot be called without naming a tenant cannot accidentally return
  another tenant's rows (Part 16).
* **Domain objects in, domain objects out.** No ORM instance, session,
  ``Row``, or SQL string crosses this boundary in either direction.
* **Read models are explicit dataclasses**, not dicts, so Phase 5 gets a
  typed contract rather than a bag of keys.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Sequence

from domain.attack_paths.models import AttackPath
from domain.findings.models import Finding
from domain.resources.models import NormalizedResource
from domain.scans.lifecycle import LifecycleState, LogicalFinding
from domain.scans.models import Scan, ScanError, ScanStatus
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import ResourceId, TenantId


# ---------------------------------------------------------------------
# Read models — the typed shapes Phase 5's API will serialize.
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComplianceSnapshot:
    """The compliance posture at one scan — Part 9's core question,
    "what was the compliance score during scan X?", answered without
    recomputing anything.

    ``score`` is deliberately ``fail``-vs-``pass`` only: INDETERMINATE
    findings are excluded from the denominator rather than counted as
    passes. Counting unknowns as compliant is precisely the "hidden
    compliance" the rule engine's three-valued logic exists to prevent,
    and it must not be reintroduced by an averaging formula.
    """

    scan_key: str
    tenant_id: TenantId
    provider: CloudProvider
    account_id: str | None
    scanned_at: datetime
    status: ScanStatus
    resource_count: int
    finding_count: int
    pass_count: int
    fail_count: int
    indeterminate_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    @property
    def score(self) -> float | None:
        """Percentage of DETERMINATE checks that passed, 0-100.

        ``None`` when nothing determinate was evaluated — an honest
        "unknown", never a misleading 100%.
        """

        determinate = self.pass_count + self.fail_count
        if determinate == 0:
            return None
        return round(100.0 * self.pass_count / determinate, 2)


@dataclass(frozen=True, slots=True)
class FindingHistoryEntry:
    """One appearance of a logical finding in one scan — the row behind
    ``GET /findings/{logical_finding_id}/history``.
    """

    scan_key: str
    scanned_at: datetime
    status: str
    severity: Severity
    finding_id: str


@dataclass(frozen=True, slots=True)
class SeverityBreakdown:
    """Findings grouped by a dimension (severity / domain / provider) —
    Phase 6's dashboard widgets.
    """

    dimension: str
    value: str
    count: int


# ---------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------


class ScanRepository(ABC):
    """Write-side lifecycle of a ``Scan``."""

    @abstractmethod
    def create(self, scan: Scan) -> None:
        """Persist a newly created (QUEUED) scan.

        Idempotent on ``scan_key``: re-creating an existing scan must not
        raise, so a retried scan launch cannot leave a half-written row.
        """

    @abstractmethod
    def update_status(self, *, tenant_id: TenantId, scan_key: str, status: ScanStatus) -> None:
        """Move a scan to a new status. Illegal transitions are rejected
        by the ``Scan`` aggregate before reaching here; this only
        persists the outcome.
        """

    @abstractmethod
    def save(self, scan: Scan) -> None:
        """Persist the full current state of a scan (status, counts,
        completion time, errors). Used at every terminal transition.
        """

    @abstractmethod
    def get(self, *, tenant_id: TenantId, scan_key: str) -> Scan | None:
        """Fetch one scan, or ``None``. Tenant-scoped: a scan belonging
        to another tenant returns ``None``, never the row.
        """

    @abstractmethod
    def list_recent(self, *, tenant_id: TenantId, limit: int = 50, offset: int = 0) -> tuple[Scan, ...]:
        """Most-recent-first scan history — ``GET /scans``."""

    @abstractmethod
    def record_errors(self, *, tenant_id: TenantId, scan_key: str, errors: Sequence[ScanError]) -> None:
        """Persist structured partial-failure records (Part 19)."""


class ResourceSnapshotRepository(ABC):
    """What the cloud looked like during a scan (Part 5)."""

    @abstractmethod
    def save_all(
        self, *, tenant_id: TenantId, scan_key: str, resources: Sequence[NormalizedResource]
    ) -> int:
        """Bulk-persist every resource observed in a scan.

        Bulk by contract, not by convenience: a per-row INSERT loop over
        a large account is the classic way this subsystem becomes the
        bottleneck (Part 15). Returns the number of rows written.
        """

    @abstractmethod
    def get_for_scan(self, *, tenant_id: TenantId, scan_key: str) -> tuple[NormalizedResource, ...]:
        """Reconstruct the observed state of a scan — the audit and
        debugging path.
        """

    @abstractmethod
    def get_resource_history(
        self, *, tenant_id: TenantId, resource_id: ResourceId, limit: int = 50
    ) -> tuple[tuple[str, NormalizedResource], ...]:
        """``(scan_key, snapshot)`` pairs for one resource over time."""


class FindingSnapshotRepository(ABC):
    """Per-scan finding observations (Part 6)."""

    @abstractmethod
    def save_all(self, *, tenant_id: TenantId, scan_key: str, findings: Sequence[Finding]) -> int:
        """Bulk-persist a scan's findings. Returns rows written."""

    @abstractmethod
    def get_for_scan(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        status: str | None = None,
        severity: Severity | None = None,
    ) -> tuple[Finding, ...]:
        """``GET /scans/{scan_key}/findings``, with the two filters a
        dashboard always applies.
        """

    @abstractmethod
    def get_by_id(self, *, tenant_id: TenantId, finding_id: str) -> Finding | None:
        """``GET /findings/{finding_id}``."""

    @abstractmethod
    def get_history(
        self, *, tenant_id: TenantId, logical_finding_id: str, limit: int = 100
    ) -> tuple[FindingHistoryEntry, ...]:
        """``GET /findings/{logical_finding_id}/history`` — every scan in
        which this issue appeared.
        """


class LogicalFindingRepository(ABC):
    """The cross-scan lifecycle (Part 7)."""

    @abstractmethod
    def get_active(self, *, tenant_id: TenantId) -> tuple[LogicalFinding, ...]:
        """Every OPEN or REOPENED finding — the "what is wrong right
        now" query.
        """

    @abstractmethod
    def get_by_logical_ids(
        self, *, tenant_id: TenantId, logical_ids: Sequence[str]
    ) -> Mapping[str, LogicalFinding]:
        """Bulk lookup used by lifecycle reconciliation. Bulk because
        reconciliation compares a whole scan's findings at once; N+1
        lookups here would dominate persist time.
        """

    @abstractmethod
    def upsert_all(self, *, tenant_id: TenantId, logical_findings: Sequence[LogicalFinding]) -> int:
        """Insert-or-update lifecycle rows in bulk."""

    @abstractmethod
    def get_by_state(
        self, *, tenant_id: TenantId, state: LifecycleState, limit: int = 100
    ) -> tuple[LogicalFinding, ...]:
        """Filter by lifecycle state — powers "resolved this month" and
        "recurring findings" dashboard panels.
        """


class ScanHistoryQueryRepository(ABC):
    """Read-only analytics spanning several tables (Parts 9, 25, 26).

    Deliberately separate from the write-side repositories: these are the
    queries Phase 5 and Phase 6 will hit constantly, and keeping them in
    one port makes the indexes they depend on explicit and reviewable.
    """

    @abstractmethod
    def get_compliance_snapshot(self, *, tenant_id: TenantId, scan_key: str) -> ComplianceSnapshot | None:
        """"What was the compliance score during scan X?\""""

    @abstractmethod
    def get_compliance_history(
        self,
        *,
        tenant_id: TenantId,
        provider: CloudProvider | None = None,
        account_id: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> tuple[ComplianceSnapshot, ...]:
        """The compliance trend line — ``GET /compliance/history``."""

    @abstractmethod
    def count_findings_by(
        self, *, tenant_id: TenantId, scan_key: str, dimension: str
    ) -> tuple[SeverityBreakdown, ...]:
        """Group a scan's FAILING findings by ``severity``, ``domain``,
        ``provider``, or ``rule_id`` — the dashboard's breakdown widgets.
        """

    @abstractmethod
    def get_rule_regressions(
        self, *, tenant_id: TenantId, limit: int = 50
    ) -> tuple[LogicalFinding, ...]:
        """"Which rule regressed?" — findings that were resolved and came
        back, most-recently-reopened first.
        """


class AttackPathRepository(ABC):
    """Persist and read back discovered attack paths (STEP 4).

    ``save_all`` must be **idempotent**: re-persisting an identical scan
    writes the same rows rather than duplicating them. Attack path ids
    are deterministic composites, so a conflict on
    ``(attack_path_id, scan_key)`` means "we already recorded this exact
    path in this exact scan" — not an error.

    Reads return plain mappings rather than ``AttackPath`` aggregates.
    The aggregate's invariants are construction-time guarantees over live
    graph objects; rebuilding it from JSONB would either re-validate
    against a graph that no longer exists or force those invariants to be
    relaxed — and an aggregate relaxed so it can be read back has stopped
    meaning anything.
    """

    @abstractmethod
    def save_all(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        attack_paths: Sequence[AttackPath],
        created_at: datetime,
    ) -> int:
        """Persist paths, returning how many rows were written."""

    @abstractmethod
    def get_for_scan(self, *, tenant_id: TenantId, scan_key: str) -> tuple[dict, ...]:
        """Every path from one scan, highest risk first."""

    @abstractmethod
    def get_by_id(self, *, tenant_id: TenantId, attack_path_id: str) -> dict | None:
        """One path, or ``None``. Never another tenant's."""
