from application.conformance.models import ConformanceOutcome, ConformanceReport, ConformanceResult
from application.conformance.report import all_fully_conformant, render_summary
from domain.shared.identifiers import RuleId


def make_report(scenario_id, results):
    return ConformanceReport(scenario_id=scenario_id, results=tuple(results))


def make_result(rule_id, outcome, detail="detail"):
    return ConformanceResult(scenario_id="s", rule_id=RuleId(rule_id), outcome=outcome, detail=detail)


class TestRenderSummary:
    def test_conformant_scenario_is_labeled_conformant(self) -> None:
        report = make_report("s3-public-bucket", [make_result("rule-1", ConformanceOutcome.PASS)])
        text = render_summary((report,))
        assert "[CONFORMANT] s3-public-bucket" in text

    def test_non_conformant_scenario_is_labeled_and_lists_the_failing_result(self) -> None:
        report = make_report(
            "s3-public-bucket", [make_result("rule-1", ConformanceOutcome.WRONG_STATUS, detail="expected FAIL got PASS")]
        )
        text = render_summary((report,))
        assert "[NON-CONFORMANT] s3-public-bucket" in text
        assert "wrong_status: rule-1" in text
        assert "expected FAIL got PASS" in text

    def test_passing_results_are_not_individually_listed(self) -> None:
        report = make_report("s3-public-bucket", [make_result("rule-1", ConformanceOutcome.PASS)])
        text = render_summary((report,))
        assert "rule-1" not in text

    def test_aggregate_counts_are_included(self) -> None:
        reports = (
            make_report("s1", [make_result("rule-1", ConformanceOutcome.PASS)]),
            make_report("s2", [make_result("rule-2", ConformanceOutcome.MISSING_FINDING)]),
        )
        text = render_summary(reports)
        assert "Scenarios: 2" in text
        assert "Rule assertions: 2" in text
        assert "pass: 1" in text
        assert "missing_finding: 1" in text

    def test_empty_reports_renders_without_error(self) -> None:
        text = render_summary(())
        assert "Scenarios: 0" in text

    def test_rendering_is_deterministic(self) -> None:
        report = make_report(
            "s3-public-bucket",
            [
                make_result("rule-1", ConformanceOutcome.PASS),
                make_result("rule-2", ConformanceOutcome.WRONG_SEVERITY),
            ],
        )
        first = render_summary((report,))
        second = render_summary((report,))
        assert first == second


class TestAllFullyConformant:
    def test_true_when_every_report_is_conformant(self) -> None:
        reports = (
            make_report("s1", [make_result("rule-1", ConformanceOutcome.PASS)]),
            make_report("s2", [make_result("rule-2", ConformanceOutcome.PASS)]),
        )
        assert all_fully_conformant(reports) is True

    def test_false_when_any_report_is_not_conformant(self) -> None:
        reports = (
            make_report("s1", [make_result("rule-1", ConformanceOutcome.PASS)]),
            make_report("s2", [make_result("rule-2", ConformanceOutcome.FALSE_NEGATIVE)]),
        )
        assert all_fully_conformant(reports) is False

    def test_true_for_empty_reports(self) -> None:
        assert all_fully_conformant(()) is True
