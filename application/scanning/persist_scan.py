"""``PersistScanResult`` — the use case that turns an ephemeral
``ScanResult`` into durable history (Phase 4).

This is where Phase 3 stopped and Phase 4 begins. It owns two things no
other component can own:

1. **The transaction boundary** (Part 14). A scan's resources, findings,
   lifecycle rows and summary counts are one atomic fact. Half of them
   is worse than none: a findings table without its summary, or findings
   without the resource snapshots that explain them, is a security
   record nobody can trust.

2. **Lifecycle reconciliation** (Part 7). Deciding that a finding which
   stopped appearing is RESOLVED — and that one which came back is
   REOPENED — requires comparing this scan against all previous state.
   That comparison is application logic; the state transitions
   themselves belong to the domain (``domain.scans.lifecycle``) and are
   delegated to it, never reimplemented here.

It contains no SQL and imports no infrastructure module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from application.ports.persistence.unit_of_work import UnitOfWork
from application.scanning.dtos import ScanResult
from domain.findings.models import Finding
from domain.scans.lifecycle import LifecycleState, LogicalFinding
from domain.scans.models import Scan, ScanCounts, ScanError, ScanStatus, ScanTarget
from domain.shared.identifiers import TenantId, account_key
from domain.tenants.isolation import ensure_same_tenant


@dataclass(frozen=True, slots=True)
class PersistenceOutcome:
    """What actually happened, for logging and observability (Part 21).

    Returned rather than logged directly so the caller chooses its own
    logging stack — Phase 4 provides hooks, not an observability
    platform.
    """

    scan_key: str
    status: ScanStatus
    resources_written: int
    findings_written: int
    lifecycle_rows_written: int
    newly_resolved: int
    newly_reopened: int
    duration_seconds: float | None


class PersistScanResult:
    """Persists one ``ScanResult`` atomically, reconciling lifecycle."""

    def __init__(self, unit_of_work: UnitOfWork) -> None:
        self._uow = unit_of_work

    def execute(
        self,
        *,
        scan_result: ScanResult,
        target: ScanTarget,
        completed_at: datetime,
        errors: tuple[ScanError, ...] = (),
        scanner_version: str = "unknown",
        ruleset_version: str = "unknown",
        correlation_id: str | None = None,
    ) -> PersistenceOutcome:
        tenant_id = scan_result.tenant_id
        self._verify_tenant(scan_result, tenant_id)

        scan = Scan.create(
            tenant_id=tenant_id,
            target=target,
            started_at=scan_result.scanned_at,
            scanner_version=scanner_version,
            ruleset_version=ruleset_version,
            correlation_id=correlation_id,
            legacy_scan_id=scan_result.scan_id,
        ).start()

        counts = ScanCounts.from_scan_data(
            resources=scan_result.resources, findings=scan_result.findings, errors=errors
        )

        # A scan that hit collection errors is PARTIAL, never COMPLETED —
        # the domain aggregate refuses the alternative. See
        # domain/scans/models.py:ScanStatus.
        if errors:
            final = scan.complete_partially(completed_at=completed_at, counts=counts, errors=errors)
        else:
            final = scan.complete(completed_at=completed_at, counts=counts)

        with self._uow as uow:
            uow.scans.create(scan)

            resources_written = uow.resource_snapshots.save_all(
                tenant_id=tenant_id, scan_key=final.scan_key, resources=scan_result.resources
            )
            findings_written = uow.finding_snapshots.save_all(
                tenant_id=tenant_id, scan_key=final.scan_key, findings=scan_result.findings
            )

            # Attack paths (STEP 4). Previously computed and then
            # discarded here — only their risk survived, via
            # Finding.related_attack_path_ids. `created_at` is the SCAN's
            # own time, for the same reason lifecycle timestamps are:
            # both record when the cloud was in this state, not when the
            # database happened to be written.
            uow.attack_paths.save_all(
                tenant_id=tenant_id,
                scan_key=final.scan_key,
                attack_paths=scan_result.attack_paths,
                created_at=scan_result.scanned_at,
            )

            # Lifecycle timestamps use the SCAN's own time, not the
            # persistence time. `first_seen_at` must agree with the
            # finding's `detected_at` (both are "when the cloud was in
            # this state"), otherwise an audit comparing a finding to its
            # lifecycle row sees two different discovery dates — and the
            # discrepancy would grow with however long persistence took.
            reconciled, resolved, reopened = self._reconcile_lifecycle(
                uow=uow,
                scan_result=scan_result,
                scan_key=final.scan_key,
                observed_at=scan_result.scanned_at,
            )
            lifecycle_written = uow.logical_findings.upsert_all(
                tenant_id=tenant_id, logical_findings=reconciled
            )

            if errors:
                uow.scans.record_errors(tenant_id=tenant_id, scan_key=final.scan_key, errors=errors)

            # Summary written LAST, inside the same transaction, so the
            # counts can never describe rows that failed to land.
            uow.scans.save(final)
            uow.commit()

        return PersistenceOutcome(
            scan_key=final.scan_key,
            status=final.status,
            resources_written=resources_written,
            findings_written=findings_written,
            lifecycle_rows_written=lifecycle_written,
            newly_resolved=resolved,
            newly_reopened=reopened,
            duration_seconds=final.duration_seconds,
        )

    # -- lifecycle reconciliation --------------------------------------

    def _reconcile_lifecycle(
        self, *, uow: UnitOfWork, scan_result: ScanResult, scan_key: str, observed_at: datetime
    ) -> tuple[tuple[LogicalFinding, ...], int, int]:
        """Compare this scan against known lifecycle state.

        Three cases:

        * **Failing now, not tracked** -> new OPEN lifecycle row.
        * **Failing now, already tracked** -> ``observed_again``
          (which promotes RESOLVED -> REOPENED inside the domain).
        * **Tracked and active, but this scan covered its resource and
          did NOT fail** -> ``resolve``.

        The third case carries the important precondition: a finding is
        only resolved when its resource was genuinely re-examined. A
        resource missing because collection failed has not been fixed,
        and closing it would silently retire a live security issue. The
        ``covered_resources`` set is what enforces that.
        """

        tenant_id = scan_result.tenant_id

        # Built with an explicit loop rather than a comprehension so the
        # `logical_finding_id is not None` narrowing is visible to the
        # type checker as well as the reader. A finding without a logical
        # id cannot be lifecycle-tracked at all (it has no stable
        # cross-scan identity), so it is skipped rather than guessed at.
        failing_by_logical_id: dict[str, Finding] = {}
        for candidate in scan_result.findings:
            logical_id = candidate.logical_finding_id
            if candidate.status.value == "fail" and logical_id is not None:
                failing_by_logical_id[logical_id] = candidate

        # Only resources this scan actually observed can have their
        # findings resolved.
        #
        # Keyed by the FULL identity — (provider, account, resource id) —
        # not by resource id alone. Resource ids are unique only within
        # an account: `bucket-1` in account 222… is a different bucket
        # from `bucket-1` in account 111…, and an S3 bucket and an Azure
        # storage account can share a name outright. Matching on the bare
        # id would let a scan of one account silently resolve a live
        # finding in another — the worst possible failure mode, because
        # the issue disappears from the dashboard without being fixed.
        covered_resources = {
            (r.cloud_provider, account_key(r.account_id), r.resource_id)
            for r in scan_result.resources
        }

        known = uow.logical_findings.get_by_logical_ids(
            tenant_id=tenant_id, logical_ids=list(failing_by_logical_id)
        )
        active = uow.logical_findings.get_active(tenant_id=tenant_id)

        reconciled: list[LogicalFinding] = []
        reopened = 0
        resolved = 0

        for logical_id, finding in failing_by_logical_id.items():
            existing = known.get(logical_id)
            if existing is None:
                reconciled.append(
                    LogicalFinding.first_observation(
                        finding=finding,
                        provider=scan_result.provider,
                        seen_at=observed_at,
                        scan_key=scan_key,
                    )
                )
                continue
            was_resolved = existing.state is LifecycleState.RESOLVED
            updated = existing.observed_again(
                seen_at=observed_at, scan_key=scan_key, severity=finding.severity
            )
            if was_resolved and updated.state is LifecycleState.REOPENED:
                reopened += 1
            reconciled.append(updated)

        for tracked in active:
            if tracked.logical_finding_id in failing_by_logical_id:
                continue
            if (
                tracked.provider,
                account_key(tracked.account_id),
                tracked.resource_id,
            ) not in covered_resources:
                # Not re-examined this scan — leave it alone.
                continue
            reconciled.append(tracked.resolve(resolved_at=observed_at, scan_key=scan_key))
            resolved += 1

        return tuple(reconciled), resolved, reopened

    @staticmethod
    def _verify_tenant(scan_result: ScanResult, tenant_id: TenantId) -> None:
        """Defense in depth: refuse to persist anything carrying a
        foreign tenant, even though upstream already checked.
        """

        for resource in scan_result.resources:
            ensure_same_tenant(tenant_id, resource.tenant_id, context="persisted resource")
        for finding in scan_result.findings:
            ensure_same_tenant(tenant_id, finding.tenant_id, context="persisted finding")
