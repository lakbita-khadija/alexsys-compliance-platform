from datetime import datetime, timezone

import pytest

from application.conformance.models import (
    ActualFinding,
    ConformanceOutcome,
    ConformanceReport,
    ConformanceResult,
    ExpectedFinding,
    Scenario,
)
from application.errors import ConformanceError
from domain.findings.models import FindingStatus
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_resource() -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId("bucket-1"),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes={"public": True},
        tags={},
        relationships=(),
        collected_at=COLLECTED_AT,
    )


def make_expected(rule_id="rule-1", status=FindingStatus.FAIL, **overrides) -> ExpectedFinding:
    return ExpectedFinding(rule_id=RuleId(rule_id), status=status, **overrides)


class TestScenario:
    def test_valid_scenario(self) -> None:
        scenario = Scenario(
            scenario_id="s3-public-bucket",
            description="a public bucket",
            resource=make_resource(),
            expected_findings=(make_expected(),),
        )
        assert scenario.scenario_id == "s3-public-bucket"

    def test_blank_scenario_id_is_rejected(self) -> None:
        with pytest.raises(ConformanceError):
            Scenario(scenario_id="  ", description="x", resource=make_resource(), expected_findings=(make_expected(),))

    def test_empty_expected_findings_is_rejected(self) -> None:
        with pytest.raises(ConformanceError):
            Scenario(scenario_id="s3-public-bucket", description="x", resource=make_resource(), expected_findings=())

    def test_graph_and_resources_by_id_default_to_none(self) -> None:
        scenario = Scenario(
            scenario_id="s3-public-bucket",
            description="x",
            resource=make_resource(),
            expected_findings=(make_expected(),),
        )
        assert scenario.graph is None
        assert scenario.resources_by_id is None


class TestExpectedFinding:
    def test_minimal_expected_finding(self) -> None:
        expected = make_expected()
        assert expected.severity is None
        assert expected.evidence_contains == ()

    def test_expected_finding_with_all_fields(self) -> None:
        expected = make_expected(severity=Severity.CRITICAL, evidence_contains=("is public",))
        assert expected.severity is Severity.CRITICAL
        assert expected.evidence_contains == ("is public",)


class TestActualFinding:
    def test_actual_finding_carries_no_scan_scoped_identity(self) -> None:
        actual = ActualFinding(
            rule_id=RuleId("rule-1"),
            resource_id=ResourceId("bucket-1"),
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            evidence={"public": True},
        )
        # No `id`, `scan_id`, or `detected_at` field exists on this type at all.
        assert not hasattr(actual, "id")
        assert not hasattr(actual, "scan_id")


class TestConformanceResult:
    def test_is_conformant_true_for_pass(self) -> None:
        result = ConformanceResult(
            scenario_id="s3-public-bucket", rule_id=RuleId("rule-1"), outcome=ConformanceOutcome.PASS, detail="ok"
        )
        assert result.is_conformant is True

    @pytest.mark.parametrize(
        "outcome",
        [o for o in ConformanceOutcome if o is not ConformanceOutcome.PASS],
    )
    def test_is_conformant_false_for_every_other_outcome(self, outcome) -> None:
        result = ConformanceResult(scenario_id="s3-public-bucket", rule_id=RuleId("rule-1"), outcome=outcome, detail="x")
        assert result.is_conformant is False


class TestConformanceReport:
    def test_fully_conformant_when_all_results_pass(self) -> None:
        report = ConformanceReport(
            scenario_id="s3-public-bucket",
            results=(
                ConformanceResult(
                    scenario_id="s3-public-bucket", rule_id=RuleId("rule-1"), outcome=ConformanceOutcome.PASS, detail="ok"
                ),
            ),
        )
        assert report.is_fully_conformant is True

    def test_not_fully_conformant_when_any_result_fails(self) -> None:
        report = ConformanceReport(
            scenario_id="s3-public-bucket",
            results=(
                ConformanceResult(
                    scenario_id="s3-public-bucket", rule_id=RuleId("rule-1"), outcome=ConformanceOutcome.PASS, detail="ok"
                ),
                ConformanceResult(
                    scenario_id="s3-public-bucket",
                    rule_id=RuleId("rule-2"),
                    outcome=ConformanceOutcome.WRONG_STATUS,
                    detail="bad",
                ),
            ),
        )
        assert report.is_fully_conformant is False

    def test_outcome_counts(self) -> None:
        report = ConformanceReport(
            scenario_id="s3-public-bucket",
            results=(
                ConformanceResult(
                    scenario_id="s3-public-bucket", rule_id=RuleId("rule-1"), outcome=ConformanceOutcome.PASS, detail="ok"
                ),
                ConformanceResult(
                    scenario_id="s3-public-bucket", rule_id=RuleId("rule-2"), outcome=ConformanceOutcome.PASS, detail="ok"
                ),
                ConformanceResult(
                    scenario_id="s3-public-bucket",
                    rule_id=RuleId("rule-3"),
                    outcome=ConformanceOutcome.MISSING_FINDING,
                    detail="x",
                ),
            ),
        )
        assert report.outcome_counts == {ConformanceOutcome.PASS: 2, ConformanceOutcome.MISSING_FINDING: 1}

    def test_empty_report_is_fully_conformant(self) -> None:
        report = ConformanceReport(scenario_id="s3-public-bucket", results=())
        assert report.is_fully_conformant is True
        assert report.outcome_counts == {}
