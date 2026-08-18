"""The PostgreSQL ``UnitOfWork`` (Phase 4, Part 14).

One session, one transaction, every repository sharing it. Because all
five repositories are built from the SAME ``Session``, they provably
participate in one transaction — the alternative (each repository
opening its own connection) is how "atomic" persistence quietly stops
being atomic.

Rollback is structural, not remembered: ``__exit__`` rolls back unless
``commit()`` was called, so an exception — or an early return added by a
future refactor — cannot leave a half-written scan behind.
"""

from __future__ import annotations

from types import TracebackType

from sqlalchemy.orm import Session, sessionmaker

from application.ports.persistence.unit_of_work import UnitOfWork
from infrastructure.persistence.postgres.repositories.scan_repository import (
    PostgresAttackPathRepository,
    PostgresFindingSnapshotRepository,
    PostgresLogicalFindingRepository,
    PostgresResourceSnapshotRepository,
    PostgresScanHistoryQueryRepository,
    PostgresScanRepository,
)


class PostgresUnitOfWork(UnitOfWork):
    """A transactional scope backed by one SQLAlchemy ``Session``.

    Re-enterable: ``__enter__`` opens a fresh session each time, so one
    instance can be reused across scans (as ``PersistScanResult`` does
    when persisting several scans in sequence).
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._session: Session | None = None
        self._committed = False

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError(
                "PostgresUnitOfWork used outside a `with` block — the transaction is not open"
            )
        return self._session

    def __enter__(self) -> "PostgresUnitOfWork":
        self._session = self._session_factory()
        self._committed = False

        self.scans = PostgresScanRepository(self._session)
        self.resource_snapshots = PostgresResourceSnapshotRepository(self._session)
        self.finding_snapshots = PostgresFindingSnapshotRepository(self._session)
        self.logical_findings = PostgresLogicalFindingRepository(self._session)
        self.history = PostgresScanHistoryQueryRepository(self._session)
        self.attack_paths = PostgresAttackPathRepository(self._session)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if not self._committed:
                # Covers BOTH the exception path and the
                # forgot-to-commit path. Neither should persist anything.
                self.rollback()
        finally:
            if self._session is not None:
                self._session.close()
                self._session = None

    def commit(self) -> None:
        self.session.commit()
        self._committed = True

    def rollback(self) -> None:
        if self._session is not None:
            self._session.rollback()
