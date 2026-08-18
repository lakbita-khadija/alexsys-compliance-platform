"""Asynchronous scan submission (Phase 5, §26).

``POST /api/v1/scans`` returns ``202 Accepted`` with a scan id. It does
not wait for the scan: enumerating a real cloud account is hundreds of
throttled API calls, and holding an HTTP connection open for that long
fails behind any load balancer.

The sequencing is what makes this safe to restart and honest to observe:

1. Derive the scan key and persist the scan as ``QUEUED`` **first**,
   inside its own transaction.
2. Only then submit the job.
3. Return the id.

Persisting before submitting means a scan can never run without a record
of it existing. The reverse order has a window where the job starts,
does real work, and nothing in the database knows — so a crash leaves no
trace of a scan that touched production infrastructure.

The worker then drives the existing Phase 4 machinery: ``ScanCloudAccount``
to collect/normalize/evaluate, ``PersistScanResult`` to store atomically
and reconcile finding lifecycle, and ``ComputeScoresForScan`` to score.
None of those are reimplemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from application.compliance.query_scores import ComputeScoresForScan
from application.ports.audit import AuditRecorder
from application.ports.auth import AuthenticatedIdentity, Role
from application.ports.jobs import ScanJobRunner
from application.ports.persistence.unit_of_work import UnitOfWork
from application.ports.system import Clock
from application.scanning.dtos import ScanConfiguration
from application.scanning.persist_scan import PersistScanResult
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.audit.models import AuditAction
from domain.scans.models import Scan, ScanStatus, ScanTarget
from domain.shared.identifiers import TenantId


class ScanConflict(Exception):
    """A scan for this exact target and instant already exists and is
    still running. Maps to HTTP 409.

    Possible precisely because scan keys are deterministic (Phase 4 §4):
    the same target at the same instant derives the same key. That is a
    feature — it makes a duplicate submission detectable instead of
    silently producing two concurrent scans of the same account.
    """


@dataclass(frozen=True, slots=True)
class ScanSubmission:
    """What ``POST /scans`` returns — an id and a status, never results.

    Deliberately minimal. A submission response that included findings
    would imply the scan had finished, which is the exact misconception
    §26 asks the contract to avoid.
    """

    scan_key: str
    status: ScanStatus
    tenant_id: TenantId
    submitted_at: datetime


class SubmitScan:
    """Accept a scan request, persist it as QUEUED, and hand it off."""

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        job_runner: ScanJobRunner,
        clock: Clock,
        audit: AuditRecorder,
        scan_worker: "ScanWorker",
    ) -> None:
        self._uow = unit_of_work
        self._jobs = job_runner
        self._clock = clock
        self._audit = audit
        self._worker = scan_worker

    def execute(
        self,
        *,
        identity: AuthenticatedIdentity,
        target: ScanTarget,
        correlation_id: str | None = None,
        scanner_version: str = "unknown",
        ruleset_version: str = "unknown",
    ) -> ScanSubmission:
        # Triggering a scan is not a read. It spends money and hits real
        # cloud APIs, so it needs its own role rather than riding along
        # with READER.
        identity.require_role(Role.SCANNER)

        submitted_at = self._clock.now()
        tenant_id = identity.tenant_id

        scan = Scan.create(
            tenant_id=tenant_id,
            target=target,
            started_at=submitted_at,
            scanner_version=scanner_version,
            ruleset_version=ruleset_version,
            correlation_id=correlation_id,
        )

        with self._uow as uow:
            existing = uow.scans.get(tenant_id=tenant_id, scan_key=scan.scan_key)
            if existing is not None and not existing.status.is_terminal:
                raise ScanConflict(
                    f"a scan for this target is already {existing.status.value}"
                )
            uow.scans.create(scan)
            uow.commit()

        self._audit.record(
            tenant_id=tenant_id,
            actor_subject=identity.subject,
            action=AuditAction.SCAN_STARTED,
            resource=scan.scan_key,
            resource_type="scan",
            correlation_id=correlation_id,
            metadata={
                "provider": target.provider.value,
                "account_id": target.account_id,
            },
        )

        # Submitted only after the row is durably committed above.
        self._jobs.submit(
            lambda: self._worker.run(
                tenant_id=tenant_id,
                scan_key=scan.scan_key,
                target=target,
                correlation_id=correlation_id,
            ),
            job_name=f"scan:{target.provider.value}",
        )

        return ScanSubmission(
            scan_key=scan.scan_key,
            status=scan.status,
            tenant_id=tenant_id,
            submitted_at=submitted_at,
        )


class GetScan:
    """``GET /api/v1/scans/{scan_key}`` — tenant-scoped scan status."""

    def __init__(self, unit_of_work: UnitOfWork) -> None:
        self._uow = unit_of_work

    def execute(self, *, identity: AuthenticatedIdentity, scan_key: str) -> Scan | None:
        identity.require_role(Role.READER)
        with self._uow as uow:
            # Same indistinguishability rule as findings: another
            # tenant's scan is reported as absent, not as forbidden.
            return uow.scans.get(tenant_id=identity.tenant_id, scan_key=scan_key)


class ListScans:
    """``GET /api/v1/scans`` — recent scans, newest first."""

    def __init__(self, unit_of_work: UnitOfWork) -> None:
        self._uow = unit_of_work

    def execute(
        self, *, identity: AuthenticatedIdentity, limit: int = 50, offset: int = 0
    ) -> tuple[Scan, ...]:
        identity.require_role(Role.READER)
        with self._uow as uow:
            return uow.scans.list_recent(
                tenant_id=identity.tenant_id, limit=limit, offset=offset
            )


class ScanWorker:
    """Runs the scan pipeline outside the request cycle.

    Lives in the application layer, not infrastructure, because it is
    orchestration: it decides the ORDER of collect → evaluate → persist →
    score, and what happens when a step fails. Which thread or queue
    executes it is the infrastructure concern, and that sits behind
    ``ScanJobRunner``.

    The invariant that matters: **every exit path leaves the scan in a
    terminal state**. A worker that raised and left a scan RUNNING
    forever would be worse than one that failed loudly — the API would
    report "in progress" indefinitely and nobody would know to retry.
    """

    def __init__(
        self,
        *,
        scan_cloud_account: ScanCloudAccount,
        persist_scan_result: PersistScanResult,
        compute_scores: ComputeScoresForScan,
        unit_of_work: UnitOfWork,
        clock: Clock,
        audit: AuditRecorder,
        credentials_reference: str,
        scan_configuration: ScanConfiguration,
    ) -> None:
        self._scan = scan_cloud_account
        self._persist = persist_scan_result
        self._compute_scores = compute_scores
        self._uow = unit_of_work
        self._clock = clock
        self._audit = audit
        self._credentials_reference = credentials_reference
        self._scan_configuration = scan_configuration

    def run(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        target: ScanTarget,
        correlation_id: str | None = None,
    ) -> None:
        """Execute one scan end to end, never raising into the runner."""

        started_at = self._clock.now()
        self._mark(tenant_id=tenant_id, scan_key=scan_key, status=ScanStatus.RUNNING)

        try:
            result = self._scan.run(
                tenant_id=tenant_id,
                provider=target.provider,
                credentials_reference=self._credentials_reference,
                scan_configuration=self._scan_configuration,
                scanned_at=started_at,
            )

            # PersistScanResult owns the transaction boundary and the
            # finding-lifecycle reconciliation; neither is duplicated here.
            outcome = self._persist.execute(
                scan_result=result,
                target=target,
                completed_at=self._clock.now(),
            )

            # Scored from the same finding set that was just persisted,
            # so a score can never describe findings that failed to land.
            self._compute_scores.execute(
                tenant_id=tenant_id,
                scan_key=outcome.scan_key,
                findings=result.findings,
                computed_at=self._clock.now(),
            )

            self._audit.record(
                tenant_id=tenant_id,
                actor_subject="complianceiq-core",
                actor_kind="system",
                action=AuditAction.SCAN_COMPLETED,
                resource=outcome.scan_key,
                resource_type="scan",
                correlation_id=correlation_id,
                metadata={
                    "status": outcome.status.value,
                    "resources": outcome.resources_written,
                    "findings": outcome.findings_written,
                },
            )

        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            # A scan can fail for any reason a cloud API can invent.
            # Whatever it was, the scan must not be left RUNNING, and the
            # exception must not escape into the job runner's thread
            # where nothing would handle it.
            self._mark(tenant_id=tenant_id, scan_key=scan_key, status=ScanStatus.FAILED)
            self._audit.record(
                tenant_id=tenant_id,
                actor_subject="complianceiq-core",
                actor_kind="system",
                action=AuditAction.SCAN_FAILED,
                resource=scan_key,
                resource_type="scan",
                correlation_id=correlation_id,
                # The exception TYPE, never its message: a provider
                # error string can quote a request that contains
                # sensitive parameters.
                metadata={"error_type": type(exc).__name__},
            )

    def _mark(self, *, tenant_id: TenantId, scan_key: str, status: ScanStatus) -> None:
        """Move the persisted scan to ``status`` in its own transaction.

        Separate from the main persistence transaction on purpose: the
        whole point of marking a scan FAILED is that the main
        transaction did not commit.
        """

        with self._uow as uow:
            uow.scans.update_status(tenant_id=tenant_id, scan_key=scan_key, status=status)
            uow.commit()
