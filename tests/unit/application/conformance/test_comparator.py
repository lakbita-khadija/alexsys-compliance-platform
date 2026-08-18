from datetime import datetime, timezone

from application.conformance.comparator import ConformanceComparator
from application.conformance.models import ActualFinding, ConformanceOutcome, ExpectedFinding, Scenario
from domain.findings.models import FindingStatus
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
RESOURCE_ID = ResourceId("bucket-1")
OTHER_RESOURCE_ID = ResourceId("bucket-2")


def make_resource(resource_id=RESOURCE_ID) -> NormalizedResource:
    return NormalizedResource(
        resource_id=resource_id,
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes={},
        tags={},
        relationships=(),
        collected_at=COLLECTED_AT,
    )


def make_scenario(expected_findings) -> Scenario:
    return Scenario(
        scenario_id="scenario-1",
        description="test",
        resource=make_resource(),
        expected_findings=expected_findings,
    )


def make_actual(rule_id="rule-1", resource_id=RESOURCE_ID, status=FindingStatus.FAIL, severity=Severity.HIGH, evidence=None):
    return ActualFinding(
        rule_id=RuleId(rule_id), resource_id=resource_id, status=status, severity=severity, evidence=evidence or {}
    )


def make_expected(rule_id="rule-1", status=FindingStatus.FAIL, **overrides):
    return ExpectedFinding(rule_id=RuleId(rule_id), status=status, **overrides)


class TestConformancePass:
    def test_matching_status_only_is_pass(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL),))
        actual = (make_actual(status=FindingStatus.FAIL),)
        report = ConformanceComparator().compare(scenario, actual)
        assert len(report.results) == 1
        assert report.results[0].outcome is ConformanceOutcome.PASS

    def test_matching_status_and_severity_is_pass(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL, severity=Severity.CRITICAL),))
        actual = (make_actual(status=FindingStatus.FAIL, severity=Severity.CRITICAL),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.PASS

    def test_matching_evidence_substring_is_pass(self) -> None:
        scenario = make_scenario((make_expected(evidence_contains=("bucket-1 is public",)),))
        actual = (make_actual(evidence={"narrative": "bucket-1 is public and unencrypted"}),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.PASS


class TestMissingFinding:
    def test_no_actual_finding_for_expected_rule_id(self) -> None:
        scenario = make_scenario((make_expected(rule_id="rule-does-not-exist"),))
        report = ConformanceComparator().compare(scenario, ())
        assert report.results[0].outcome is ConformanceOutcome.MISSING_FINDING


class TestWrongResource:
    def test_actual_finding_belongs_to_a_different_resource(self) -> None:
        scenario = make_scenario((make_expected(),))
        actual = (make_actual(resource_id=OTHER_RESOURCE_ID),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.WRONG_RESOURCE


class TestFalsePositiveAndNegative:
    def test_expected_pass_actual_fail_is_false_positive(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.PASS),))
        actual = (make_actual(status=FindingStatus.FAIL),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.FALSE_POSITIVE

    def test_expected_fail_actual_pass_is_false_negative(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL),))
        actual = (make_actual(status=FindingStatus.PASS),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.FALSE_NEGATIVE


class TestWrongStatus:
    def test_expected_fail_actual_indeterminate_is_wrong_status_not_false_negative(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL),))
        actual = (make_actual(status=FindingStatus.INDETERMINATE),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.WRONG_STATUS

    def test_expected_indeterminate_actual_pass_is_wrong_status(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.INDETERMINATE),))
        actual = (make_actual(status=FindingStatus.PASS),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.WRONG_STATUS


class TestWrongSeverity:
    def test_status_matches_but_severity_does_not(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL, severity=Severity.CRITICAL),))
        actual = (make_actual(status=FindingStatus.FAIL, severity=Severity.LOW),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.WRONG_SEVERITY

    def test_no_severity_assertion_means_severity_is_never_checked(self) -> None:
        scenario = make_scenario((make_expected(status=FindingStatus.FAIL),))
        actual = (make_actual(status=FindingStatus.FAIL, severity=Severity.LOW),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.PASS


class TestWrongEvidence:
    def test_missing_expected_evidence_substring(self) -> None:
        scenario = make_scenario((make_expected(evidence_contains=("not present anywhere",)),))
        actual = (make_actual(evidence={"narrative": "something else entirely"}),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.WRONG_EVIDENCE

    def test_evidence_check_falls_back_to_raw_dict_when_no_narrative(self) -> None:
        scenario = make_scenario((make_expected(evidence_contains=("True",)),))
        actual = (make_actual(evidence={"public": True}),)
        report = ConformanceComparator().compare(scenario, actual)
        assert report.results[0].outcome is ConformanceOutcome.PASS


class TestUnexpectedFinding:
    def test_unclaimed_failing_actual_finding_is_unexpected(self) -> None:
        scenario = make_scenario((make_expected(rule_id="rule-1", status=FindingStatus.FAIL),))
        actual = (
            make_actual(rule_id="rule-1", status=FindingStatus.FAIL),
            make_actual(rule_id="rule-2", status=FindingStatus.FAIL),
        )
        report = ConformanceComparator().compare(scenario, actual)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("rule-1")] is ConformanceOutcome.PASS
        assert outcomes[RuleId("rule-2")] is ConformanceOutcome.UNEXPECTED_FINDING

    def test_unclaimed_passing_actual_finding_is_not_reported_at_all(self) -> None:
        scenario = make_scenario((make_expected(rule_id="rule-1", status=FindingStatus.FAIL),))
        actual = (
            make_actual(rule_id="rule-1", status=FindingStatus.FAIL),
            make_actual(rule_id="rule-2", status=FindingStatus.PASS),
        )
        report = ConformanceComparator().compare(scenario, actual)
        assert len(report.results) == 1

    def test_unclaimed_indeterminate_actual_finding_is_not_reported_at_all(self) -> None:
        scenario = make_scenario((make_expected(rule_id="rule-1", status=FindingStatus.FAIL),))
        actual = (
            make_actual(rule_id="rule-1", status=FindingStatus.FAIL),
            make_actual(rule_id="rule-2", status=FindingStatus.INDETERMINATE),
        )
        report = ConformanceComparator().compare(scenario, actual)
        assert len(report.results) == 1


class TestWrongRule:
    def test_actual_finding_rule_id_disagrees_with_the_expectation_it_is_matched_against(self) -> None:
        # This exercises `_classify_expected` directly rather than
        # through `compare()`: canonicalization (pass 1) keys the
        # actual-findings dict by each finding's own rule_id, so a
        # lookup hit through the public `compare()` path can never
        # disagree with its key — this branch is a defensive guard
        # against a *future* canonicalization change (e.g. matching by
        # position instead of by rule_id) silently pairing the wrong
        # records, not something reachable through today's public API.
        comparator = ConformanceComparator()
        scenario = make_scenario((make_expected(rule_id="rule-1"),))
        mismatched_actual = make_actual(rule_id="rule-2")
        result = comparator._classify_expected(scenario, make_expected(rule_id="rule-1"), mismatched_actual)
        assert result.outcome is ConformanceOutcome.WRONG_RULE


class TestDeterminism:
    def test_results_are_sorted_by_rule_id(self) -> None:
        scenario = make_scenario(
            (
                make_expected(rule_id="zzz-rule"),
                make_expected(rule_id="aaa-rule"),
                make_expected(rule_id="mmm-rule"),
            )
        )
        actual = (
            make_actual(rule_id="zzz-rule"),
            make_actual(rule_id="aaa-rule"),
            make_actual(rule_id="mmm-rule"),
        )
        report = ConformanceComparator().compare(scenario, actual)
        assert [str(r.rule_id) for r in report.results] == ["aaa-rule", "mmm-rule", "zzz-rule"]

    def test_comparison_is_repeatable(self) -> None:
        scenario = make_scenario((make_expected(),))
        actual = (make_actual(),)
        comparator = ConformanceComparator()
        first = comparator.compare(scenario, actual)
        second = comparator.compare(scenario, actual)
        assert first.results == second.results
