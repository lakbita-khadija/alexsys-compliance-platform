from datetime import datetime, timezone

import pytest

from domain.compliance.models import (
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceStatus,
    ControlMapping,
)
from domain.findings.models import FindingStatus
from domain.shared.identifiers import RuleId, TenantId

TENANT = TenantId("acme")
EVALUATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
FRAMEWORK = ComplianceFramework(id="cis-aws", name="CIS AWS Foundations", version="1.5.0")


class TestComplianceFramework:
    def test_valid_framework(self) -> None:
        assert FRAMEWORK.name == "CIS AWS Foundations"

    def test_blank_id_is_rejected(self) -> None:
        with pytest.raises(Exception):
            ComplianceFramework(id="", name="CIS", version="1.0")


class TestControlMapping:
    def test_valid_mapping(self) -> None:
        mapping = ControlMapping(
            framework=FRAMEWORK, control_id="CIS-1.1", rule_ids=(RuleId("rule-1"), RuleId("rule-2"))
        )
        assert mapping.rule_ids == (RuleId("rule-1"), RuleId("rule-2"))

    def test_mapping_may_have_no_rules_yet(self) -> None:
        mapping = ControlMapping(framework=FRAMEWORK, control_id="CIS-1.1", rule_ids=())
        assert mapping.rule_ids == ()

    def test_blank_control_id_is_rejected(self) -> None:
        with pytest.raises(Exception):
            ControlMapping(framework=FRAMEWORK, control_id="", rule_ids=())


class TestComplianceAssessmentTimestamp:
    def test_evaluated_at_must_be_timezone_aware(self) -> None:
        with pytest.raises(Exception):
            ComplianceAssessment.from_findings(
                tenant_id=TENANT,
                framework=FRAMEWORK,
                control_id="CIS-1.1",
                statuses=[FindingStatus.PASS],
                evaluated_at=datetime(2026, 1, 1),
            )


class TestComplianceAssessment:
    def test_all_passing_findings_yield_compliant(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[FindingStatus.PASS, FindingStatus.PASS],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.status is ComplianceStatus.COMPLIANT

    def test_any_failing_finding_yields_non_compliant(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[FindingStatus.PASS, FindingStatus.FAIL],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.status is ComplianceStatus.NON_COMPLIANT

    def test_indeterminate_findings_with_no_failures_yield_unknown(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[FindingStatus.PASS, FindingStatus.INDETERMINATE],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.status is ComplianceStatus.UNKNOWN

    def test_no_evidence_at_all_never_becomes_silently_compliant(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.status is ComplianceStatus.UNKNOWN

    def test_failure_takes_precedence_over_indeterminate(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[FindingStatus.INDETERMINATE, FindingStatus.FAIL],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.status is ComplianceStatus.NON_COMPLIANT

    def test_assessment_is_tenant_scoped(self) -> None:
        assessment = ComplianceAssessment.from_findings(
            tenant_id=TENANT,
            framework=FRAMEWORK,
            control_id="CIS-1.1",
            statuses=[FindingStatus.PASS],
            evaluated_at=EVALUATED_AT,
        )
        assert assessment.tenant_id == TENANT

    def test_assessment_is_deterministic(self) -> None:
        statuses = [FindingStatus.PASS, FindingStatus.FAIL, FindingStatus.INDETERMINATE]
        results = {
            ComplianceAssessment.from_findings(
                tenant_id=TENANT,
                framework=FRAMEWORK,
                control_id="CIS-1.1",
                statuses=statuses,
                evaluated_at=EVALUATED_AT,
            ).status
            for _ in range(20)
        }
        assert results == {ComplianceStatus.NON_COMPLIANT}
