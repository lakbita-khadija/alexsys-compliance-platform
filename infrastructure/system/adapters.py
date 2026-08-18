"""Concrete adapters for the ambient-capability ports (Phase 5).

Small, boring, and isolated here so that ``datetime.now()`` and
``uuid4()`` appear in exactly one module instead of being scattered
through the application layer — which is what keeps every use case
testable without freezing time globally.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from application.ports.audit import AuditRecorder
from application.ports.jobs import ScanJob, ScanJobRunner
from application.ports.queries import AuditEventRepository
from application.ports.system import Clock, IdGenerator
from domain.audit.models import AuditAction, AuditActor, AuditEvent
from domain.shared.identifiers import TenantId

logger = logging.getLogger("complianceiq.system")


class SystemClock(Clock):
    """The real clock. Always timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FrozenClock(Clock):
    """A clock that does not move, for tests and fixtures.

    Shipped in ``infrastructure`` rather than a test helper because the
    deterministic AI contract fixtures (§31) are generated with it, and
    those are a product artifact.
    """

    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime")
        self._instant = instant

    def now(self) -> datetime:
        return self._instant

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self._instant = self._instant + timedelta(seconds=seconds)


class UuidGenerator(IdGenerator):
    """UUID4 identifiers."""

    def new_id(self) -> str:
        return str(uuid.uuid4())


class SequentialIdGenerator(IdGenerator):
    """Predictable ids for tests and fixtures: ``prefix-1``, ``prefix-2``…"""

    def __init__(self, prefix: str = "id") -> None:
        self._prefix = prefix
        self._counter = 0
        self._lock = threading.Lock()

    def new_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"{self._prefix}-{self._counter}"


class InlineScanJobRunner(ScanJobRunner):
    """Runs the job immediately, on the calling thread.

    For tests and for the local core-stub, where a scan must be finished
    by the time the next assertion runs. **Not** for production: it makes
    ``POST /scans`` synchronous again, which is the exact behaviour §26
    exists to avoid. Named so that is obvious at the wiring site.
    """

    def submit(self, job: ScanJob, *, job_name: str) -> None:
        try:
            job()
        except Exception:  # noqa: BLE001 - mirrors the threaded runner's contract
            logger.exception("inline scan job failed", extra={"job_name": job_name})


class ThreadScanJobRunner(ScanJobRunner):
    """Runs jobs on background daemon threads.

    Adequate for a single-instance deployment and dependency-free. Its
    honest limitations, both consequences of having no durable queue:

    * a process restart loses running jobs. Because ``ScanWorker`` marks
      the scan RUNNING before starting, such a scan is visible as
      RUNNING-but-stale rather than vanishing — recoverable, but it does
      need a reaper that Phase 5 does not ship.
    * there is no retry and no backpressure beyond ``max_workers``.

    Swap in a real queue by implementing ``ScanJobRunner``; no use case
    changes.
    """

    def __init__(self, *, max_workers: int = 4) -> None:
        from concurrent.futures import ThreadPoolExecutor

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="ciq-scan"
        )

    def submit(self, job: ScanJob, *, job_name: str) -> None:
        def _guarded() -> None:
            try:
                job()
            except Exception:  # noqa: BLE001
                # The HTTP caller received 202 long ago; there is nobody
                # to raise to. ScanWorker already marks the scan FAILED,
                # so this is the last-resort net for a failure in that
                # marking itself.
                logger.exception("scan job failed", extra={"job_name": job_name})

        self._executor.submit(_guarded)

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


class RepositoryAuditRecorder(AuditRecorder):
    """Assembles ``AuditEvent``s and appends them to a repository.

    Never raises into the caller. An audit sink that is briefly
    unavailable must not fail a scan that already ran — the failure is
    logged at ERROR so it is visible, but the operation proceeds.

    That is a real trade-off: a deployment with a regulatory requirement
    for guaranteed audit capture would need the opposite (fail closed),
    and would change this class rather than every call site.
    """

    def __init__(
        self,
        *,
        repository: AuditEventRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._ids = id_generator

    def record(
        self,
        *,
        tenant_id: TenantId,
        actor_subject: str,
        action: AuditAction,
        resource: str | None = None,
        resource_type: str | None = None,
        correlation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        actor_kind: str = "client",
    ) -> None:
        try:
            event = AuditEvent(
                event_id=self._ids.new_id(),
                tenant_id=tenant_id,
                actor=AuditActor(subject=actor_subject, kind=actor_kind),
                action=action,
                occurred_at=self._clock.now(),
                resource=resource,
                resource_type=resource_type,
                correlation_id=correlation_id,
                metadata=dict(metadata or {}),
            )
            self._repository.record(event)
        except Exception:  # noqa: BLE001
            logger.exception(
                "failed to record audit event",
                extra={"action": action.value, "correlation_id": correlation_id},
            )
