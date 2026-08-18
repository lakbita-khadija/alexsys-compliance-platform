"""Compliance scoring (Phase 5, §11).

Phase 4 already computes a score, but only as a property on one read
model (``ComplianceSnapshot.score``) covering exactly one scope: a whole
scan. Phase 5's API must serve a score *per framework*, *per domain* and
*per tenant* as well, and the dashboard will eventually plot how each
moves over time. That makes scoring a domain concept in its own right
rather than an incidental attribute, so it lives here.

Two properties matter more than the arithmetic:

**Determinism.** The same findings always produce the same score. No
clock is read, no randomness, no floating-point accumulation order
dependence — the inputs are integer counts and the division happens
once. An auditor who recomputes last quarter's score must get last
quarter's number.

**No hidden compliance.** INDETERMINATE findings are excluded from the
denominator, never counted as passes. This is the single most important
decision in the module and it is deliberately repeated from
``ComplianceSnapshot.score``: Phase 3 built three-valued logic precisely
so "we could not check this" never masquerades as "this is fine", and an
averaging formula that rounds unknowns up to compliant would reintroduce
exactly that failure one layer higher.

A scope with nothing determinate to measure scores ``None`` — an honest
"unknown", never a misleading 100%.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable

from domain.findings.models import Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.errors import DomainError
from domain.shared.identifiers import TenantId
from domain.shared.temporal import is_timezone_aware


class InvalidComplianceScore(DomainError):
    """A ``ComplianceScore`` was constructed with incoherent data."""


class ScoreScope(str, Enum):
    """What a score is measuring.

    A closed vocabulary because each value implies a different
    ``scope_value`` semantic, and an open-ended scope string would make
    the stored rows impossible to interpret without guessing.
    """

    #: Everything known for the tenant at this point in time.
    TENANT = "tenant"
    #: One compliance framework (``iso_27001``, ``soc_2``, …).
    FRAMEWORK = "framework"
    #: One risk domain (``iam``, ``network``, ``encryption``, …).
    DOMAIN = "domain"
    #: One scan execution — the Phase 4 ``ComplianceSnapshot`` scope.
    SCAN = "scan"


@dataclass(frozen=True, slots=True)
class ScoreCounts:
    """The raw tallies a score is computed from.

    Stored alongside the score rather than discarded, because a bare
    percentage is not auditable: "73.5%" is unfalsifiable, whereas
    "203 passed, 73 failed, 12 could not be evaluated" can be checked
    against the findings themselves. It is also what lets a dashboard
    show a breakdown without recomputing anything.
    """

    passed: int = 0
    failed: int = 0
    indeterminate: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def __post_init__(self) -> None:
        for name in ("passed", "failed", "indeterminate", "critical", "high", "medium", "low"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise InvalidComplianceScore(f"{name} must be a non-negative integer, got {value!r}")

    @property
    def determinate(self) -> int:
        """Checks that actually produced a verdict.

        The denominator. INDETERMINATE is excluded here, which is the
        whole point — see the module docstring.
        """

        return self.passed + self.failed

    @property
    def total(self) -> int:
        """Every check evaluated, including the ones that could not be
        determined. Used for coverage, never as a score denominator.
        """

        return self.determinate + self.indeterminate

    @property
    def failing_by_severity(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
        }


@dataclass(frozen=True, slots=True)
class ComplianceScore:
    """A deterministic compliance score for one scope, at one moment.

    ``scope_value`` is the thing being measured: the framework id for
    ``FRAMEWORK``, the domain name for ``DOMAIN``, the scan key for
    ``SCAN``, and ``None`` for ``TENANT`` (whose scope value is the
    tenant itself, already carried by ``tenant_id``).
    """

    tenant_id: TenantId
    scope: ScoreScope
    scope_value: str | None
    counts: ScoreCounts
    computed_at: datetime
    #: The scan this score was computed from, when it came from one.
    #: Present for SCAN scope, and for the others when they were
    #: computed over a single scan's findings.
    scan_key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidComplianceScore("tenant_id must be a TenantId")
        if not isinstance(self.scope, ScoreScope):
            raise InvalidComplianceScore("scope must be a ScoreScope")
        if not isinstance(self.counts, ScoreCounts):
            raise InvalidComplianceScore("counts must be a ScoreCounts")
        if not isinstance(self.computed_at, datetime) or not is_timezone_aware(self.computed_at):
            raise InvalidComplianceScore("computed_at must be a timezone-aware datetime")

        # TENANT is the only scope whose value is implied by tenant_id.
        # Every other scope is meaningless without one: a FRAMEWORK score
        # that does not say which framework is not a score, it is a
        # number.
        if self.scope is ScoreScope.TENANT:
            if self.scope_value is not None:
                raise InvalidComplianceScore(
                    "TENANT scope must not carry a scope_value (the tenant is already identified)"
                )
        elif not isinstance(self.scope_value, str) or not self.scope_value.strip():
            raise InvalidComplianceScore(f"{self.scope.value} scope requires a non-blank scope_value")

        if self.scan_key is not None and not self.scan_key.strip():
            raise InvalidComplianceScore("scan_key must be None or a non-blank string")

    @property
    def score(self) -> float | None:
        """Percentage of DETERMINATE checks that passed, 0–100.

        ``None`` when nothing determinate was evaluated. Callers must
        render that as "no data" rather than substituting a number;
        every alternative default is a lie in one direction or the
        other.
        """

        if self.counts.determinate == 0:
            return None
        return round(100.0 * self.counts.passed / self.counts.determinate, 2)

    @property
    def coverage(self) -> float | None:
        """Percentage of evaluated checks that could actually be
        determined, 0–100.

        The honesty companion to ``score``. A 100% score computed from
        4 determinate checks out of 900 is not a good posture, it is an
        absent one, and only this number makes that visible.
        """

        if self.counts.total == 0:
            return None
        return round(100.0 * self.counts.determinate / self.counts.total, 2)

    @property
    def is_measurable(self) -> bool:
        return self.counts.determinate > 0


def tally(findings: Iterable[Finding]) -> ScoreCounts:
    """Count findings into ``ScoreCounts``.

    Severity is tallied over FAILING findings only. A passing check is
    not a "low-severity finding"; counting it as one would make the
    severity breakdown meaningless — the same rule Phase 4's
    ``ScanCounts.from_scan_data`` applies, kept consistent on purpose.
    """

    passed = failed = indeterminate = 0
    by_severity = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}

    for finding in findings:
        if finding.status is FindingStatus.PASS:
            passed += 1
        elif finding.status is FindingStatus.FAIL:
            failed += 1
            by_severity[finding.severity] += 1
        else:
            indeterminate += 1

    return ScoreCounts(
        passed=passed,
        failed=failed,
        indeterminate=indeterminate,
        critical=by_severity[Severity.CRITICAL],
        high=by_severity[Severity.HIGH],
        medium=by_severity[Severity.MEDIUM],
        low=by_severity[Severity.LOW],
    )


def score_for_scope(
    *,
    tenant_id: TenantId,
    scope: ScoreScope,
    scope_value: str | None,
    findings: Iterable[Finding],
    computed_at: datetime,
    scan_key: str | None = None,
) -> ComplianceScore:
    """Build one ``ComplianceScore`` from the findings in that scope.

    ``computed_at`` is passed in, never read from a clock here — the
    domain stays deterministic and testable, exactly as Phases 1–4 do.
    """

    return ComplianceScore(
        tenant_id=tenant_id,
        scope=scope,
        scope_value=scope_value,
        counts=tally(findings),
        computed_at=computed_at,
        scan_key=scan_key,
    )


def scores_by_dimension(
    *,
    tenant_id: TenantId,
    scope: ScoreScope,
    findings: Iterable[Finding],
    computed_at: datetime,
    scan_key: str | None = None,
) -> tuple[ComplianceScore, ...]:
    """Group findings by ``framework`` or ``domain`` and score each group.

    Returned sorted by ``scope_value`` so the output is deterministic —
    an API that returns the same data in a different order on every call
    breaks pagination and makes responses impossible to diff.
    """

    if scope not in (ScoreScope.FRAMEWORK, ScoreScope.DOMAIN):
        raise InvalidComplianceScore(
            f"scores_by_dimension supports FRAMEWORK and DOMAIN, not {scope.value}"
        )

    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        key = finding.framework if scope is ScoreScope.FRAMEWORK else finding.domain
        grouped.setdefault(key, []).append(finding)

    return tuple(
        score_for_scope(
            tenant_id=tenant_id,
            scope=scope,
            scope_value=key,
            findings=group,
            computed_at=computed_at,
            scan_key=scan_key,
        )
        for key, group in sorted(grouped.items())
    )
