"""``ConformanceComparator`` — the Expected-vs-Actual comparison engine
(Phase 3B design proposal, Part K).

This is the one place in the whole conformance framework that decides
"did the scan get it right." It is deliberately NOT a rule evaluator:
it never calls ``domain.rules.conditions.evaluate_condition`` or
``Rule.evaluate`` itself, and it never re-derives what a resource
*should* trigger — it only compares an ``ExpectedFinding`` (declared by
a human, in a scenario fixture) against an ``ActualFinding`` (produced
by the real ``application.rules.evaluate_rules.EvaluateRules``, run
elsewhere — see ``runner.py``).

Three deterministic passes, matching Part K exactly:

1. **Canonicalize** — index every ``ActualFinding`` by its ``rule_id``
   (a stable key; a scenario is single-resource, so ``rule_id`` alone
   is unambiguous). A ``dict`` keyed this way, not a list scanned
   linearly — comparison never depends on the order actual findings
   happened to be produced in.
2. **Match by stable key + classify** — for every ``ExpectedFinding``,
   look up its ``rule_id`` in the canonical actual index and classify
   the result (see ``_classify_expected``).
3. **Classify the leftovers** — every ``ActualFinding`` whose
   ``rule_id`` was never claimed by an expectation, but whose status is
   FAIL, is an ``UNEXPECTED_FINDING`` — a rule fired against this
   scenario's resource that nobody predicted it would (see
   ``_classify_unexpected``).

Every classification compares individual, named fields
(``status``/``severity``/``evidence``) — never ``expected == actual``
on the dataclass as a whole, and the final report is always sorted by
``rule_id`` for deterministic ordering, never dict/set iteration order
(Part K: "never ordering-dependent").
"""

from __future__ import annotations

from application.conformance.models import (
    ActualFinding,
    ConformanceOutcome,
    ConformanceReport,
    ConformanceResult,
    ExpectedFinding,
    Scenario,
)
from domain.findings.models import FindingStatus
from domain.shared.identifiers import RuleId


class ConformanceComparator:
    """Stateless — every method is a pure function of its arguments."""

    def compare(self, scenario: Scenario, actual_findings: tuple[ActualFinding, ...]) -> ConformanceReport:
        actual_by_rule_id: dict[RuleId, ActualFinding] = {f.rule_id: f for f in actual_findings}
        claimed_rule_ids: set[RuleId] = set()

        results: list[ConformanceResult] = []
        for expected in scenario.expected_findings:
            claimed_rule_ids.add(expected.rule_id)
            actual = actual_by_rule_id.get(expected.rule_id)
            results.append(self._classify_expected(scenario, expected, actual))

        for finding in actual_findings:
            if finding.rule_id in claimed_rule_ids:
                continue
            if finding.status is not FindingStatus.FAIL:
                continue
            results.append(self._classify_unexpected(scenario, finding))

        results.sort(key=lambda r: str(r.rule_id))
        return ConformanceReport(scenario_id=scenario.scenario_id, results=tuple(results))

    def _classify_expected(
        self, scenario: Scenario, expected: ExpectedFinding, actual: ActualFinding | None
    ) -> ConformanceResult:
        if actual is None:
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=ConformanceOutcome.MISSING_FINDING,
                detail=f"expected a finding for rule {expected.rule_id!s}, but the rule catalog produced none "
                "(check the rule_id for a typo, or whether the rule was removed/renamed)",
                expected=expected,
            )

        if actual.resource_id != scenario.resource.resource_id:
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=ConformanceOutcome.WRONG_RESOURCE,
                detail=f"actual finding is for resource {actual.resource_id!s}, not the scenario's own resource "
                f"{scenario.resource.resource_id!s}",
                expected=expected,
                actual=actual,
            )

        if actual.rule_id != expected.rule_id:
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=ConformanceOutcome.WRONG_RULE,
                detail=f"expected rule {expected.rule_id!s} but the matched finding is for rule {actual.rule_id!s}",
                expected=expected,
                actual=actual,
            )

        if actual.status != expected.status:
            if expected.status is FindingStatus.PASS and actual.status is FindingStatus.FAIL:
                outcome = ConformanceOutcome.FALSE_POSITIVE
                detail = f"rule {expected.rule_id!s} was expected to PASS but FAILed — a false alarm on this resource"
            elif expected.status is FindingStatus.FAIL and actual.status is FindingStatus.PASS:
                outcome = ConformanceOutcome.FALSE_NEGATIVE
                detail = f"rule {expected.rule_id!s} was expected to FAIL but PASSed — a missed violation on this resource"
            else:
                outcome = ConformanceOutcome.WRONG_STATUS
                detail = f"rule {expected.rule_id!s} expected status {expected.status.value}, got {actual.status.value}"
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=outcome,
                detail=detail,
                expected=expected,
                actual=actual,
            )

        if expected.severity is not None and actual.severity != expected.severity:
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=ConformanceOutcome.WRONG_SEVERITY,
                detail=f"rule {expected.rule_id!s} expected severity {expected.severity.value}, got {actual.severity.value}",
                expected=expected,
                actual=actual,
            )

        if expected.evidence_contains and not self._evidence_contains_all(actual, expected.evidence_contains):
            missing = [s for s in expected.evidence_contains if s not in self._evidence_text(actual)]
            return ConformanceResult(
                scenario_id=scenario.scenario_id,
                rule_id=expected.rule_id,
                outcome=ConformanceOutcome.WRONG_EVIDENCE,
                detail=f"rule {expected.rule_id!s} evidence is missing expected substring(s): {missing!r}",
                expected=expected,
                actual=actual,
            )

        return ConformanceResult(
            scenario_id=scenario.scenario_id,
            rule_id=expected.rule_id,
            outcome=ConformanceOutcome.PASS,
            detail=f"rule {expected.rule_id!s} matched every declared expectation",
            expected=expected,
            actual=actual,
        )

    def _classify_unexpected(self, scenario: Scenario, actual: ActualFinding) -> ConformanceResult:
        return ConformanceResult(
            scenario_id=scenario.scenario_id,
            rule_id=actual.rule_id,
            outcome=ConformanceOutcome.UNEXPECTED_FINDING,
            detail=f"rule {actual.rule_id!s} FAILed against this resource, but the scenario declared no expectation "
            "for it — either the scenario fixture is incomplete, or this is a genuine, previously-unnoticed "
            "rule interaction",
            actual=actual,
        )

    @staticmethod
    def _evidence_text(actual: ActualFinding) -> str:
        narrative = actual.evidence.get("narrative")
        if isinstance(narrative, str) and narrative:
            return narrative
        return repr(dict(actual.evidence))

    @classmethod
    def _evidence_contains_all(cls, actual: ActualFinding, substrings: tuple[str, ...]) -> bool:
        text = cls._evidence_text(actual)
        return all(substring in text for substring in substrings)
