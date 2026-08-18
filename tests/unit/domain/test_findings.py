from datetime import datetime, timezone

import pytest

from domain.findings.models import Evidence, Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.errors import InvalidFinding
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_finding(**overrides) -> Finding:
    defaults = dict(
        id=FindingId("finding-1"),
        tenant_id=TenantId("acme"),
        resource_id=ResourceId("bucket-1"),
        rule_id=RuleId("rule-1"),
        framework="CIS",
        control_id="CIS-1.1",
        domain="storage",
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        evidence=Evidence(data={"encrypted": False}),
        detected_at=DETECTED_AT,
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestEvidence:
    def test_valid_evidence(self) -> None:
        evidence = Evidence(data={"encrypted": False})
        assert evidence.data["encrypted"] is False

    def test_evidence_data_is_immutable(self) -> None:
        evidence = Evidence(data={"encrypted": False})
        with pytest.raises(TypeError):
            evidence.data["encrypted"] = True  # type: ignore[index]

    def test_evidence_may_be_empty(self) -> None:
        assert Evidence(data={}).data == {}


class TestFinding:
    def test_valid_finding(self) -> None:
        finding = make_finding()
        assert finding.id == FindingId("finding-1")
        assert finding.tenant_id == TenantId("acme")
        assert finding.resource_id == ResourceId("bucket-1")

    def test_finding_always_identifies_tenant_and_resource(self) -> None:
        with pytest.raises(TypeError):
            Finding(  # type: ignore[call-arg]
                id=FindingId("finding-1"),
                resource_id=ResourceId("bucket-1"),
                rule_id=RuleId("rule-1"),
                framework="CIS",
                control_id="CIS-1.1",
                domain="storage",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence=Evidence(data={}),
                detected_at=DETECTED_AT,
            )

    @pytest.mark.parametrize("bad_field", ["framework", "control_id", "domain"])
    def test_blank_metadata_is_rejected(self, bad_field) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(**{bad_field: "   "})

    def test_severity_must_be_a_severity_enum(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(severity="high")  # type: ignore[arg-type]

    def test_status_must_be_a_finding_status_enum(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(status="fail")  # type: ignore[arg-type]

    def test_status_reflects_rule_evaluation_outcome(self) -> None:
        assert make_finding(status=FindingStatus.PASS).status is FindingStatus.PASS
        assert make_finding(status=FindingStatus.INDETERMINATE).status is FindingStatus.INDETERMINATE

    def test_detected_at_must_be_a_datetime(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(detected_at="2026-01-01")  # type: ignore[arg-type]

    def test_detected_at_must_be_timezone_aware(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(detected_at=datetime(2026, 1, 1))

    def test_finding_is_immutable(self) -> None:
        finding = make_finding()
        with pytest.raises(Exception):
            finding.status = FindingStatus.PASS  # type: ignore[misc]


class TestInternalDomainFields:
    def test_internal_fields_default_sensibly(self) -> None:
        finding = make_finding()
        assert finding.version == 1
        assert finding.superseded_by is None
        assert finding.related_attack_path_ids == ()
        assert finding.related_drift_event_ids == ()
        assert finding.risk is None
        assert finding.confidence is None
        assert finding.account_id is None
        assert finding.logical_finding_id is None

    def test_account_id_and_logical_finding_id_may_be_set(self) -> None:
        finding = make_finding(account_id="123456789012", logical_finding_id="acme:123456789012:bucket-1:s3-001")
        assert finding.account_id == "123456789012"
        assert finding.logical_finding_id == "acme:123456789012:bucket-1:s3-001"

    def test_blank_account_id_is_rejected(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(account_id="   ")

    def test_blank_logical_finding_id_is_rejected(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(logical_finding_id="   ")

    def test_internal_fields_are_plain_domain_values_not_ai_contract_types(self) -> None:
        finding = make_finding(
            scan_id="scan-1",
            rule_version="1.0.0",
            region="us-east-1",
            environment="prod",
            risk=42.5,
            confidence=80.0,
        )
        assert isinstance(finding.risk, float)
        assert isinstance(finding.confidence, float)
        assert finding.scan_id == "scan-1"

    def test_risk_and_confidence_are_bounded_when_provided(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(risk=150.0)
        with pytest.raises(InvalidFinding):
            make_finding(confidence=-1.0)

    def test_version_must_be_positive(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(version=0)

    def test_finding_cannot_supersede_itself(self) -> None:
        with pytest.raises(InvalidFinding):
            make_finding(id=FindingId("finding-1"), superseded_by=FindingId("finding-1"))

    def test_findings_module_does_not_depend_on_risk_or_ai_core(self) -> None:
        import inspect

        import domain.findings.models as findings_module

        source = inspect.getsource(findings_module)
        assert "domain.risk" not in source
        assert "domain.attack_paths" not in source
        assert "AICore" not in source
        assert "ai_core" not in source.lower()
