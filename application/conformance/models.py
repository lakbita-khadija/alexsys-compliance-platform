"""Expected-vs-Actual Conformance Framework — value models (Phase 3B
design proposal, Part K).

This framework is a TEST-FRAMEWORK-only concern: it never evaluates a
rule itself (that stays exclusively ``domain.rules.conditions`` and
``application.rules.evaluate_rules.EvaluateRules``), and it never
parses Terraform. Its only job is comparing what a scenario's author
*expects* a scan to find against what the real Rule Engine *actually*
found, and classifying the difference — see ``comparator.py``.

Five concepts, matching Part K exactly:

* ``Scenario`` — one resource (plus optional graph) and the set of
  expectations declared against it.
* ``ExpectedFinding`` — one assertion: "rule X should evaluate to
  status Y against this resource" (severity/evidence assertions are
  optional and additive).
* ``ActualFinding`` — a deliberately narrow projection of a real
  ``domain.findings.models.Finding`` down to only the fields that are
  meaningful to compare (rule_id, resource_id, status, severity,
  evidence). Scan-scoped identity (``Finding.id``, ``scan_id``,
  ``detected_at``) is dropped on purpose — comparing on physical
  finding identity would make every conformance check fail simply
  because it ran at a different time, which is not what "conformance"
  means here.
* ``ConformanceOutcome`` — the closed classification vocabulary a
  comparison can produce (Part K's ten outcomes).
* ``ConformanceResult`` / ``ConformanceReport`` — one classified
  comparison, and the aggregate of every comparison for a scenario.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Mapping

from application.errors import ConformanceError
from domain.shared.enums import Severity
from domain.shared.identifiers import ResourceId, RuleId

if TYPE_CHECKING:
    from domain.findings.models import FindingStatus
    from domain.graph.models import ResourceGraph
    from domain.resources.models import NormalizedResource


class ConformanceOutcome(str, Enum):
    """The closed classification vocabulary a scenario/rule comparison
    can resolve to (Phase 3B design proposal, Part K). Never extended
    speculatively — every value here is produced by exactly one branch
    of ``comparator.ConformanceComparator``.
    """

    PASS = "pass"
    MISSING_FINDING = "missing_finding"
    UNEXPECTED_FINDING = "unexpected_finding"
    WRONG_RULE = "wrong_rule"
    WRONG_RESOURCE = "wrong_resource"
    WRONG_STATUS = "wrong_status"
    WRONG_SEVERITY = "wrong_severity"
    WRONG_EVIDENCE = "wrong_evidence"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    """One assertion a ``Scenario`` makes about a single rule's outcome.

    ``severity``/``evidence_contains`` are optional and additive — a
    scenario that only cares about status doesn't have to assert
    anything else. ``evidence_contains`` is a tuple of substrings that
    must all appear in the actual finding's evidence narrative — never
    a full evidence-dict equality check (Part K: "never expected ==
    actual").
    """

    rule_id: RuleId
    status: "FindingStatus"
    severity: Severity | None = None
    evidence_contains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ActualFinding:
    """A comparison-relevant projection of a real ``Finding`` — see the
    module docstring for why scan-scoped identity is dropped.
    """

    rule_id: RuleId
    resource_id: ResourceId
    status: "FindingStatus"
    severity: Severity
    evidence: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class Scenario:
    """One conformance test case: a resource (optionally with a graph,
    for relationship-based rules) and the expectations declared
    against it.
    """

    scenario_id: str
    description: str
    resource: "NormalizedResource"
    expected_findings: tuple[ExpectedFinding, ...]
    graph: "ResourceGraph | None" = None
    resources_by_id: Mapping[ResourceId, "NormalizedResource"] | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.scenario_id or not self.scenario_id.strip():
            raise ConformanceError("Scenario.scenario_id must be a non-blank string")
        if not self.expected_findings:
            raise ConformanceError("Scenario.expected_findings must not be empty — a scenario with no assertions proves nothing")


@dataclass(frozen=True, slots=True)
class ConformanceResult:
    """One classified comparison: either one ``ExpectedFinding`` versus
    its matching (or missing) ``ActualFinding``, or one unexpected
    ``ActualFinding`` with no matching expectation.
    """

    scenario_id: str
    rule_id: RuleId
    outcome: ConformanceOutcome
    detail: str
    expected: ExpectedFinding | None = None
    actual: ActualFinding | None = None

    @property
    def is_conformant(self) -> bool:
        return self.outcome is ConformanceOutcome.PASS


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """The aggregate of every ``ConformanceResult`` for one scenario.
    Ordering is always deterministic (sorted by rule_id — see
    ``comparator.py``), never dependent on dict/set iteration order.
    """

    scenario_id: str
    results: tuple[ConformanceResult, ...]

    @property
    def is_fully_conformant(self) -> bool:
        return all(r.is_conformant for r in self.results)

    @property
    def outcome_counts(self) -> Mapping[ConformanceOutcome, int]:
        counts: dict[ConformanceOutcome, int] = {}
        for result in self.results:
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
        return counts
