"""The logical finding lifecycle (Phase 4, Part 7).

A ``Finding`` in Phase 3 is a per-scan observation: "at 09:00 on Tuesday,
this rule failed on this resource." That is the right model for a scan,
and the wrong model for a security programme, which needs to answer
"is this bucket STILL public, and since when?"

``LogicalFinding`` is that second model. It is keyed on
``logical_finding_id`` — the Phase 3B identity that is stable across
scans — and tracks the issue rather than the observation.

The central rule: **findings are never deleted.** A finding that stops
appearing has been RESOLVED, which is a security event worth recording,
not an absence worth forgetting. Deleting it would destroy the evidence
that remediation happened.

Like ``domain.scans.models``, this module imports nothing outside
``domain.shared`` and the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Mapping

from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import InvalidFindingLifecycle
from domain.shared.identifiers import ResourceId, RuleId, TenantId
from domain.shared.temporal import is_timezone_aware


class LifecycleState(str, Enum):
    """Where a logical finding stands right now.

    ``REOPENED`` is deliberately distinct from ``OPEN``. Both mean "the
    issue is live", but a reopened finding is a *regression* — something
    that was fixed and broke again — which is a materially different
    signal for a security team than a problem that was never fixed. It
    usually indicates a process failure (drift, an unreviewed rollback,
    IaC not matching reality) rather than an unstarted task.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    SUPPRESSED = "suppressed"

    @property
    def is_active(self) -> bool:
        """Whether this state represents a live security issue."""

        return self in (LifecycleState.OPEN, LifecycleState.REOPENED)


#: Closed transition table.
#:
#:   OPEN ──────→ RESOLVED ──────→ REOPENED ──┐
#:     │              │                 │     │
#:     └─→ SUPPRESSED ┘                 └─────┘ (→ RESOLVED, → SUPPRESSED)
#:
#: SUPPRESSED is reachable from every active state and can return to an
#: active state when the suppression is lifted (an accepted risk being
#: un-accepted is a normal governance event).
_ALLOWED: Mapping[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.OPEN: frozenset({LifecycleState.RESOLVED, LifecycleState.SUPPRESSED, LifecycleState.OPEN}),
    LifecycleState.RESOLVED: frozenset({LifecycleState.REOPENED, LifecycleState.SUPPRESSED}),
    LifecycleState.REOPENED: frozenset(
        {LifecycleState.RESOLVED, LifecycleState.SUPPRESSED, LifecycleState.REOPENED}
    ),
    LifecycleState.SUPPRESSED: frozenset(
        {LifecycleState.OPEN, LifecycleState.REOPENED, LifecycleState.RESOLVED, LifecycleState.SUPPRESSED}
    ),
}


@dataclass(frozen=True, slots=True)
class LogicalFinding:
    """One security issue tracked across many scans.

    The identity components are stored as SEPARATE FIELDS rather than
    parsed out of ``logical_finding_id``. That string embeds ``:``, which
    also appears inside ARNs and Azure resource ids, making it
    unparseable (audit §3) — so it is treated as opaque, and the
    components are carried explicitly. The database keys uniqueness on
    the components, not on the string.
    """

    logical_finding_id: str
    tenant_id: TenantId
    provider: CloudProvider
    account_id: str | None
    resource_id: ResourceId
    rule_id: RuleId
    state: LifecycleState
    severity: Severity
    first_seen_at: datetime
    last_seen_at: datetime
    first_seen_scan_key: str
    last_seen_scan_key: str
    resolved_at: datetime | None = None
    resolved_scan_key: str | None = None
    reopen_count: int = 0
    occurrence_count: int = 1
    suppressed_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.logical_finding_id, str) or not self.logical_finding_id.strip():
            raise InvalidFindingLifecycle("logical_finding_id must be a non-blank string")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidFindingLifecycle("tenant_id must be a TenantId")
        if not isinstance(self.provider, CloudProvider):
            raise InvalidFindingLifecycle("provider must be a CloudProvider")
        if not isinstance(self.resource_id, ResourceId):
            raise InvalidFindingLifecycle("resource_id must be a ResourceId")
        if not isinstance(self.rule_id, RuleId):
            raise InvalidFindingLifecycle("rule_id must be a RuleId")
        if not isinstance(self.state, LifecycleState):
            raise InvalidFindingLifecycle("state must be a LifecycleState")
        if not isinstance(self.severity, Severity):
            raise InvalidFindingLifecycle("severity must be a Severity")
        for name in ("first_seen_at", "last_seen_at"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or not is_timezone_aware(value):
                raise InvalidFindingLifecycle(f"{name} must be a timezone-aware datetime")
        if self.last_seen_at < self.first_seen_at:
            raise InvalidFindingLifecycle("last_seen_at must not precede first_seen_at")
        if self.resolved_at is not None and not is_timezone_aware(self.resolved_at):
            raise InvalidFindingLifecycle("resolved_at must be timezone-aware when set")
        if self.reopen_count < 0 or self.occurrence_count < 1:
            raise InvalidFindingLifecycle("reopen_count must be >= 0 and occurrence_count >= 1")
        if self.state is LifecycleState.RESOLVED and self.resolved_at is None:
            raise InvalidFindingLifecycle("a RESOLVED finding must carry resolved_at")

    # -- transitions ---------------------------------------------------

    def _guard(self, target: LifecycleState) -> None:
        if target not in _ALLOWED[self.state]:
            raise InvalidFindingLifecycle(
                f"illegal lifecycle transition {self.state.value} -> {target.value}"
                f" (allowed: {sorted(s.value for s in _ALLOWED[self.state])})"
            )

    def observed_again(self, *, seen_at: datetime, scan_key: str, severity: Severity | None = None) -> "LogicalFinding":
        """The issue was detected again in a later scan.

        From RESOLVED this is a REGRESSION and becomes REOPENED with
        ``reopen_count`` incremented. From an already-active state it just
        refreshes ``last_seen``. A SUPPRESSED finding stays SUPPRESSED —
        an accepted risk that is still present is not a new alert, which
        is the entire point of suppression.
        """

        if self.state is LifecycleState.SUPPRESSED:
            return replace(
                self,
                last_seen_at=seen_at,
                last_seen_scan_key=scan_key,
                occurrence_count=self.occurrence_count + 1,
                severity=severity or self.severity,
            )

        if self.state is LifecycleState.RESOLVED:
            self._guard(LifecycleState.REOPENED)
            return replace(
                self,
                state=LifecycleState.REOPENED,
                last_seen_at=seen_at,
                last_seen_scan_key=scan_key,
                resolved_at=None,
                resolved_scan_key=None,
                reopen_count=self.reopen_count + 1,
                occurrence_count=self.occurrence_count + 1,
                severity=severity or self.severity,
            )

        self._guard(self.state)
        return replace(
            self,
            last_seen_at=seen_at,
            last_seen_scan_key=scan_key,
            occurrence_count=self.occurrence_count + 1,
            severity=severity or self.severity,
        )

    def resolve(self, *, resolved_at: datetime, scan_key: str) -> "LogicalFinding":
        """The issue was absent from a scan that DID cover its resource.

        The caller must only invoke this when the resource was genuinely
        re-scanned. A resource missing because collection failed has not
        been fixed — marking it resolved would silently close a finding
        that may still be live. ``ReconcileFindingLifecycle`` enforces
        that precondition.
        """

        if self.state is LifecycleState.SUPPRESSED:
            return replace(self, state=LifecycleState.RESOLVED, resolved_at=resolved_at, resolved_scan_key=scan_key)
        self._guard(LifecycleState.RESOLVED)
        return replace(
            self,
            state=LifecycleState.RESOLVED,
            resolved_at=resolved_at,
            resolved_scan_key=scan_key,
        )

    def suppress(self, *, reason: str) -> "LogicalFinding":
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidFindingLifecycle("suppression requires a non-blank reason")
        self._guard(LifecycleState.SUPPRESSED)
        return replace(self, state=LifecycleState.SUPPRESSED, suppressed_reason=reason)

    def unsuppress(self) -> "LogicalFinding":
        if self.state is not LifecycleState.SUPPRESSED:
            raise InvalidFindingLifecycle(f"cannot unsuppress a {self.state.value} finding")
        restored = LifecycleState.REOPENED if self.reopen_count else LifecycleState.OPEN
        return replace(self, state=restored, suppressed_reason=None)

    # -- construction --------------------------------------------------

    @classmethod
    def first_observation(
        cls, *, finding, provider: CloudProvider, seen_at: datetime, scan_key: str
    ) -> "LogicalFinding":
        """Build the lifecycle row for a finding seen for the first time.

        ``finding`` is a ``domain.findings.models.Finding``; it is typed
        loosely to avoid a domain-internal import cycle, and only its
        public attributes are read.

        ``provider`` is passed separately because ``Finding`` does not
        carry one — it is a property of the SCAN, not of the individual
        finding. It is required here because provider is part of the
        lifecycle identity: an AWS resource and an Azure resource that
        happen to share an id are two different issues.
        """

        logical_id = finding.logical_finding_id
        if not logical_id:
            raise InvalidFindingLifecycle(
                f"finding {finding.id!s} has no logical_finding_id and cannot be lifecycle-tracked"
            )
        return cls(
            logical_finding_id=logical_id,
            tenant_id=finding.tenant_id,
            provider=provider,
            account_id=finding.account_id,
            resource_id=finding.resource_id,
            rule_id=finding.rule_id,
            state=LifecycleState.OPEN,
            severity=finding.severity,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
            first_seen_scan_key=scan_key,
            last_seen_scan_key=scan_key,
        )
