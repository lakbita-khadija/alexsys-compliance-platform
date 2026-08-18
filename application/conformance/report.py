"""Human-readable rendering of ``ConformanceReport``s (Phase 3B design
proposal, Part K's "report" deliverable).

Pure formatting only — no comparison logic lives here (that's
``comparator.py``), and nothing here re-runs a scenario (that's
``runner.py``). Deterministic: the same reports always render to the
same text, since ``ConformanceReport.results`` is already sorted by
rule_id (comparator.py) and this module iterates scenario reports in
the order given rather than re-sorting by anything volatile.
"""

from __future__ import annotations

from application.conformance.models import ConformanceOutcome, ConformanceReport


def render_summary(reports: tuple[ConformanceReport, ...]) -> str:
    """A short, deterministic multi-line summary: one line per scenario
    plus an aggregate outcome-count table. Intended for CI logs / a
    quick terminal check, not a full audit artifact.
    """

    lines: list[str] = []
    total_results = 0
    aggregate_counts: dict[ConformanceOutcome, int] = {}

    for report in reports:
        total_results += len(report.results)
        for outcome, count in report.outcome_counts.items():
            aggregate_counts[outcome] = aggregate_counts.get(outcome, 0) + count

        status = "CONFORMANT" if report.is_fully_conformant else "NON-CONFORMANT"
        lines.append(f"[{status}] {report.scenario_id} ({len(report.results)} rule assertion(s))")
        if not report.is_fully_conformant:
            for result in report.results:
                if result.outcome is not ConformanceOutcome.PASS:
                    lines.append(f"    {result.outcome.value}: {result.rule_id!s} — {result.detail}")

    lines.append("")
    lines.append(f"Scenarios: {len(reports)}  Rule assertions: {total_results}")
    for outcome in ConformanceOutcome:
        count = aggregate_counts.get(outcome, 0)
        if count:
            lines.append(f"  {outcome.value}: {count}")

    return "\n".join(lines)


def all_fully_conformant(reports: tuple[ConformanceReport, ...]) -> bool:
    return all(report.is_fully_conformant for report in reports)
