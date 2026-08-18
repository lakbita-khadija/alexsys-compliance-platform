"""Compliance domain foundation — kept minimal (blueprint §3, DESIGNED).

No AI logic here (that belongs to the AI Core, a separate system per
§26). This module only aggregates already-computed ``FindingStatus``
values into a per-control compliance verdict, applying the same
no-hidden-compliance rule the rule evaluator already applies at the leaf
level (domain.rules.conditions): missing evidence is UNKNOWN, never
COMPLIANT.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Sequence

from domain.findings.models import FindingStatus
from domain.shared.errors import InvalidComplianceData
from domain.shared.identifiers import RuleId, TenantId
from domain.shared.temporal import is_timezone_aware


class ComplianceStatus(str, Enum):
    """The verdict for one control, derived from the findings that assess
    it.
    """

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ComplianceFramework:
    """A named compliance framework (e.g. CIS AWS Foundations)."""

    id: str
    name: str
    version: str

    def __post_init__(self) -> None:
        for name in ("id", "name", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidComplianceData(f"ComplianceFramework.{name} must be a non-blank string")


@dataclass(frozen=True, slots=True)
class ControlMapping:
    """Which rules assess a given framework control. A control may have
    no rules mapped yet — that is a coverage gap, not an error; it simply
    means any assessment of that control will find no evidence and
    resolve to ``UNKNOWN``.
    """

    framework: ComplianceFramework
    control_id: str
    rule_ids: tuple[RuleId, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.framework, ComplianceFramework):
            raise InvalidComplianceData("framework must be a ComplianceFramework")
        if not isinstance(self.control_id, str) or not self.control_id.strip():
            raise InvalidComplianceData("control_id must be a non-blank string")
        for rule_id in self.rule_ids:
            if not isinstance(rule_id, RuleId):
                raise InvalidComplianceData("rule_ids must contain only RuleId instances")


def _aggregate(statuses: Sequence[FindingStatus]) -> ComplianceStatus:
    if not statuses:
        # No evidence collected for this control: never silently compliant.
        return ComplianceStatus.UNKNOWN
    if any(status is FindingStatus.FAIL for status in statuses):
        return ComplianceStatus.NON_COMPLIANT
    if any(status is FindingStatus.INDETERMINATE for status in statuses):
        return ComplianceStatus.UNKNOWN
    return ComplianceStatus.COMPLIANT


@dataclass(frozen=True, slots=True)
class ComplianceAssessment:
    """The compliance verdict for one control, for one tenant, at a point
    in time.
    """

    tenant_id: TenantId
    framework: ComplianceFramework
    control_id: str
    status: ComplianceStatus
    evaluated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidComplianceData("tenant_id must be a TenantId")
        if not isinstance(self.framework, ComplianceFramework):
            raise InvalidComplianceData("framework must be a ComplianceFramework")
        if not isinstance(self.control_id, str) or not self.control_id.strip():
            raise InvalidComplianceData("control_id must be a non-blank string")
        if not isinstance(self.status, ComplianceStatus):
            raise InvalidComplianceData("status must be a ComplianceStatus")
        if not isinstance(self.evaluated_at, datetime):
            raise InvalidComplianceData("evaluated_at must be a datetime")
        if not is_timezone_aware(self.evaluated_at):
            raise InvalidComplianceData("evaluated_at must be timezone-aware")

    @classmethod
    def from_findings(
        cls,
        *,
        tenant_id: TenantId,
        framework: ComplianceFramework,
        control_id: str,
        statuses: Sequence[FindingStatus],
        evaluated_at: datetime,
    ) -> "ComplianceAssessment":
        """Aggregate the ``FindingStatus`` values of every finding that
        assesses ``control_id`` into a single verdict. Deterministic:
        FAIL always wins over INDETERMINATE, and no evidence is always
        UNKNOWN, never COMPLIANT.
        """

        return cls(
            tenant_id=tenant_id,
            framework=framework,
            control_id=control_id,
            status=_aggregate(statuses),
            evaluated_at=evaluated_at,
        )
