"""The Unit of Work port (Phase 4, Part 14).

Transaction boundaries are an APPLICATION decision, not an
infrastructure detail: "a scan's resources, findings, lifecycle rows and
summary either all land or none do" is a business invariant about the
integrity of a security record, so the Application layer must be able to
state it. What it must NOT know is how — `BEGIN`/`COMMIT`, savepoints,
connection pools and isolation levels stay behind this port.

Usage is a context manager, so the commit/rollback decision is
structural rather than remembered:

    with unit_of_work as uow:
        uow.scans.create(scan)
        uow.resource_snapshots.save_all(...)
        uow.finding_snapshots.save_all(...)
        uow.commit()
    # no commit() reached => rollback, guaranteed by __exit__

Deliberately NOT auto-committing on clean exit. An explicit ``commit()``
means a function that returns early, or one that a future refactor makes
return early, cannot silently half-persist a scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

from application.ports.persistence.repositories import (
    AttackPathRepository,
    FindingSnapshotRepository,
    LogicalFindingRepository,
    ResourceSnapshotRepository,
    ScanHistoryQueryRepository,
    ScanRepository,
)


class UnitOfWork(ABC):
    """One transactional scope exposing every repository it spans.

    The repositories are attributes rather than constructor arguments so
    that they provably share the same transaction: two repositories
    obtained from the same ``UnitOfWork`` cannot end up on different
    connections, which is the usual way "atomic" persistence quietly
    stops being atomic.
    """

    scans: ScanRepository
    resource_snapshots: ResourceSnapshotRepository
    finding_snapshots: FindingSnapshotRepository
    logical_findings: LogicalFindingRepository
    history: ScanHistoryQueryRepository
    attack_paths: AttackPathRepository

    @abstractmethod
    def __enter__(self) -> "UnitOfWork":
        """Open the transaction."""

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back unless ``commit()`` was called explicitly."""

    @abstractmethod
    def commit(self) -> None:
        """Make every write in this scope durable."""

    @abstractmethod
    def rollback(self) -> None:
        """Discard every write in this scope."""
