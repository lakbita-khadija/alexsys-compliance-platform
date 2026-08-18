"""The Scan aggregate and its supporting value objects (Phase 4).

A ``Scan`` is a DOMAIN concept, not a database row. It exists here — not
in ``application/`` or ``infrastructure/`` — because its status
transitions carry real invariants: a COMPLETED scan can never go back to
RUNNING, and a scan that observed collection errors must not be reported
as cleanly COMPLETED. Invariants belong in the Domain, so the state
machine lives with the data it protects.

This module imports nothing outside ``domain.shared`` and the standard
library. It has no notion of SQLAlchemy, sessions, tables, or SQL — that
separation is the whole point of Phase 4's layering (see
docs/architecture/phase-4-persistence.md).

Five concepts:

* ``ScanTarget``  — WHAT was scanned, provider-agnostically.
* ``ScanStatus``  — WHERE in its lifecycle a scan is.
* ``ScanError``   — a partial failure, structured and secret-free.
* ``ScanCounts``  — the denormalized summary a dashboard reads.
* ``Scan``        — the aggregate tying them together.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Mapping

from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import InvalidScan, InvalidScanTarget
from domain.shared.identifiers import TenantId, account_key
from domain.shared.temporal import is_timezone_aware


class ScanStatus(str, Enum):
    """The lifecycle state of one scan execution.

    ``PARTIAL`` is deliberately distinct from ``COMPLETED``: a scan where
    EC2 collection succeeded but KMS was denied produced real findings,
    but its coverage is incomplete. Reporting that as COMPLETED would let
    a dashboard show "0 KMS findings" when the truth is "KMS was never
    read" — the same "no hidden compliance" principle the rule engine's
    three-valued logic enforces, applied at the scan level.
    """

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATUSES


_TERMINAL_STATUSES = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}
)

#: The complete, closed transition table. Anything not listed is illegal.
#:
#: QUEUED ─→ RUNNING ─→ COMPLETED | PARTIAL | FAILED | CANCELLED
#:   └────────────────→ CANCELLED | FAILED
#:
#: Terminal states have NO outgoing transitions: a finished scan is a
#: historical fact, and history is not edited. A re-run is a new Scan.
_ALLOWED_TRANSITIONS: Mapping[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset({ScanStatus.RUNNING, ScanStatus.CANCELLED, ScanStatus.FAILED}),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}
    ),
    ScanStatus.COMPLETED: frozenset(),
    ScanStatus.PARTIAL: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.CANCELLED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """WHAT was scanned — provider-agnostic by construction.

    There is deliberately no ``aws_account_id`` or ``azure_subscription_id``
    field. Both are the same concept ("the billing/isolation scope this
    provider scopes resources to"), so both use ``account_id``:

    =========  =========================================
    Provider   ``account_id`` holds
    =========  =========================================
    AWS        the 12-digit account id
    Azure      the subscription id (a GUID)
    GCP        would hold the project id
    OCI        would hold the compartment OCID
    =========  =========================================

    ``directory_id`` carries the extra identity scope some providers have
    and AWS does not — Azure's Entra/AAD tenant. It is nullable precisely
    because it is not universal. This is what lets a new provider be added
    without a schema migration (Part 4 of the Phase 4 brief).

    NOTE the name collision hazard: ``ScanTarget.directory_id`` is a CLOUD
    concept. ComplianceIQ's own customer identifier is ``tenant_id`` on
    the ``Scan``, and the two are never mixed — the cloud account must
    never determine ComplianceIQ tenancy (blueprint §8).
    """

    provider: CloudProvider
    account_id: str | None = None
    directory_id: str | None = None
    regions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.provider, CloudProvider):
            raise InvalidScanTarget("provider must be a CloudProvider")
        for name in ("account_id", "directory_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise InvalidScanTarget(f"{name} must be None or a non-blank string")
        if not isinstance(self.regions, tuple):
            raise InvalidScanTarget("regions must be a tuple")
        for region in self.regions:
            if not isinstance(region, str) or not region.strip():
                raise InvalidScanTarget("every region must be a non-blank string")

    @property
    def scope_key(self) -> str:
        """A stable, collision-resistant key for this target.

        Used as one component of the deterministic scan key. ``|`` is the
        separator rather than ``:`` because ``:`` appears inside ARNs and
        Azure resource ids, which is exactly what made Phase 3's
        ``logical_finding_id`` unparseable (audit §3).
        """

        return f"{self.provider.value}|{account_key(self.account_id)}|{self.directory_id or '-'}"


@dataclass(frozen=True, slots=True)
class ScanError:
    """One structured, partial failure during collection.

    Deliberately NOT a free-text log line: the dashboard needs to say
    "KMS collection was denied in this scan", and an operator needs to
    know whether retrying would help.

    SECURITY: ``message`` is the only free-text field and must already be
    sanitized by the caller. Nothing here may carry a credential — see
    ``domain.scans.redaction`` for the guard applied at persist time.
    """

    provider: CloudProvider
    service: str
    operation: str
    error_code: str
    message: str
    occurred_at: datetime
    retryable: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.provider, CloudProvider):
            raise InvalidScan("ScanError.provider must be a CloudProvider")
        for name in ("service", "operation", "error_code"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidScan(f"ScanError.{name} must be a non-blank string")
        if not isinstance(self.message, str):
            raise InvalidScan("ScanError.message must be a string")
        if not isinstance(self.occurred_at, datetime) or not is_timezone_aware(self.occurred_at):
            raise InvalidScan("ScanError.occurred_at must be a timezone-aware datetime")
        if not isinstance(self.retryable, bool):
            raise InvalidScan("ScanError.retryable must be a bool")


@dataclass(frozen=True, slots=True)
class ScanCounts:
    """The denormalized per-scan summary.

    Deliberately stored rather than computed on read. Phase 6's dashboard
    asks "how many critical findings did scan X have?" on every page load;
    answering that with a COUNT over a findings table that grows without
    bound is the classic way a security dashboard becomes unusable at
    month three. These are written once, inside the same transaction that
    writes the findings, so they cannot drift from the rows they describe.
    """

    resource_count: int = 0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    indeterminate_count: int = 0
    error_count: int = 0

    def __post_init__(self) -> None:
        for name in (
            "resource_count",
            "finding_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "pass_count",
            "fail_count",
            "indeterminate_count",
            "error_count",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise InvalidScan(f"ScanCounts.{name} must be a non-negative integer, got {value!r}")

    @staticmethod
    def from_scan_data(*, resources, findings, errors=()) -> "ScanCounts":
        """Derive counts from the actual objects, so they cannot disagree.

        Severity is counted over FAILING findings only. A PASS finding
        still carries its rule's severity, and counting those would report
        a fully-compliant account as having hundreds of "critical" items —
        the single most misleading number a CSPM dashboard can show.
        """

        failing = [f for f in findings if f.status.value == "fail"]
        by_severity = {s: 0 for s in Severity}
        for finding in failing:
            by_severity[finding.severity] += 1

        return ScanCounts(
            resource_count=len(resources),
            finding_count=len(findings),
            critical_count=by_severity[Severity.CRITICAL],
            high_count=by_severity[Severity.HIGH],
            medium_count=by_severity[Severity.MEDIUM],
            low_count=by_severity[Severity.LOW],
            pass_count=sum(1 for f in findings if f.status.value == "pass"),
            fail_count=len(failing),
            indeterminate_count=sum(1 for f in findings if f.status.value == "indeterminate"),
            error_count=len(errors),
        )


@dataclass(frozen=True, slots=True)
class Scan:
    """One execution of the CSPM scanner against one target.

    Immutable: every transition returns a NEW ``Scan``. A scan's history
    is a sequence of facts, and mutating the object in place would make
    "what did this scan look like when it started?" unanswerable.
    """

    scan_key: str
    tenant_id: TenantId
    target: ScanTarget
    status: ScanStatus
    started_at: datetime
    completed_at: datetime | None = None
    counts: ScanCounts = field(default_factory=ScanCounts)
    errors: tuple[ScanError, ...] = ()
    scanner_version: str = "unknown"
    ruleset_version: str = "unknown"
    correlation_id: str | None = None
    legacy_scan_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scan_key, str) or not self.scan_key.strip():
            raise InvalidScan("scan_key must be a non-blank string")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidScan("tenant_id must be a TenantId")
        if not isinstance(self.target, ScanTarget):
            raise InvalidScan("target must be a ScanTarget")
        if not isinstance(self.status, ScanStatus):
            raise InvalidScan("status must be a ScanStatus")
        if not isinstance(self.started_at, datetime) or not is_timezone_aware(self.started_at):
            raise InvalidScan("started_at must be a timezone-aware datetime")
        if self.completed_at is not None:
            if not isinstance(self.completed_at, datetime) or not is_timezone_aware(self.completed_at):
                raise InvalidScan("completed_at must be a timezone-aware datetime")
            if self.completed_at < self.started_at:
                raise InvalidScan("completed_at must not precede started_at")
        if not isinstance(self.counts, ScanCounts):
            raise InvalidScan("counts must be a ScanCounts")
        if not isinstance(self.errors, tuple):
            raise InvalidScan("errors must be a tuple")
        if self.status.is_terminal and self.completed_at is None:
            raise InvalidScan(f"a {self.status.value} scan must have completed_at set")
        if not self.status.is_terminal and self.completed_at is not None:
            raise InvalidScan(f"a {self.status.value} scan must not have completed_at set")

    # -- lifecycle -----------------------------------------------------

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    def _transition_to(self, status: ScanStatus, *, at: datetime | None = None, **changes) -> "Scan":
        allowed = _ALLOWED_TRANSITIONS[self.status]
        if status not in allowed:
            raise InvalidScan(
                f"illegal scan transition {self.status.value} -> {status.value}"
                f" (allowed from {self.status.value}: "
                f"{sorted(s.value for s in allowed) or 'none — terminal state'})"
            )
        return replace(self, status=status, completed_at=at, **changes)

    def start(self) -> "Scan":
        return self._transition_to(ScanStatus.RUNNING)

    def complete(self, *, completed_at: datetime, counts: ScanCounts) -> "Scan":
        """Finish successfully.

        Refuses if the scan recorded errors — those must go through
        ``complete_partially``. This is the invariant that stops a
        partially-blind scan from being reported as full coverage.
        """

        if self.errors:
            raise InvalidScan(
                f"scan recorded {len(self.errors)} collection error(s) and cannot be COMPLETED; "
                "use complete_partially() so the gap in coverage stays visible"
            )
        return self._transition_to(ScanStatus.COMPLETED, at=completed_at, counts=counts)

    def complete_partially(
        self, *, completed_at: datetime, counts: ScanCounts, errors: tuple[ScanError, ...]
    ) -> "Scan":
        if not errors:
            raise InvalidScan("complete_partially() requires at least one ScanError; use complete()")
        return self._transition_to(ScanStatus.PARTIAL, at=completed_at, counts=counts, errors=errors)

    def fail(self, *, completed_at: datetime, errors: tuple[ScanError, ...] = ()) -> "Scan":
        return self._transition_to(ScanStatus.FAILED, at=completed_at, errors=errors or self.errors)

    def cancel(self, *, completed_at: datetime) -> "Scan":
        return self._transition_to(ScanStatus.CANCELLED, at=completed_at)

    # -- identity ------------------------------------------------------

    @staticmethod
    def derive_scan_key(*, tenant_id: TenantId, target: ScanTarget, started_at: datetime) -> str:
        """The deterministic primary key for a scan.

        Deliberately NOT ``uuid4()``: Phase 3 established that no identity
        in this system is random (verified by an AST check over the whole
        domain and application layers), so replaying the same scan inputs
        reproduces the same identity. That property is what makes scans
        auditable and idempotent to re-persist.

        Includes the account via ``target.scope_key`` — the omission of
        which is exactly what made Phase 3's ``scan_id`` collide across
        accounts (audit §2).
        """

        return f"{tenant_id!s}|{target.scope_key}|{started_at.isoformat()}"

    @classmethod
    def create(
        cls,
        *,
        tenant_id: TenantId,
        target: ScanTarget,
        started_at: datetime,
        scanner_version: str = "unknown",
        ruleset_version: str = "unknown",
        correlation_id: str | None = None,
        legacy_scan_id: str | None = None,
    ) -> "Scan":
        """Create a QUEUED scan with a derived key."""

        return cls(
            scan_key=cls.derive_scan_key(tenant_id=tenant_id, target=target, started_at=started_at),
            tenant_id=tenant_id,
            target=target,
            status=ScanStatus.QUEUED,
            started_at=started_at,
            scanner_version=scanner_version,
            ruleset_version=ruleset_version,
            correlation_id=correlation_id,
            legacy_scan_id=legacy_scan_id,
        )
