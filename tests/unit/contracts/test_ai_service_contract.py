from datetime import datetime, timezone

import pytest

from contracts.ai_service.enums import ExternalFindingStatus, Framework, RiskDomain
from contracts.ai_service.models import FindingContract, NormalizedResourceContract
from contracts.ai_service.translation import finding_to_contract, resource_to_contract
from contracts.errors import ContractTranslationError
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_finding(**overrides) -> Finding:
    defaults = dict(
        id=FindingId("finding-1"),
        tenant_id=TenantId("acme"),
        resource_id=ResourceId("bucket-1"),
        rule_id=RuleId("rule-1"),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        evidence=Evidence(data={"encrypted": False}),
        detected_at=DETECTED_AT,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_resource(**overrides) -> NormalizedResource:
    defaults = dict(
        resource_id=ResourceId("arn:aws:s3:::acme-data"),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="eu-west-1",
        attributes={"acl": "public-read", "encryption": None},
        tags={},
        relationships=(),
        collected_at=DETECTED_AT,
    )
    defaults.update(overrides)
    return NormalizedResource(**defaults)


class TestFindingContractShape:
    def test_valid_finding_translates(self) -> None:
        contract = finding_to_contract(make_finding())
        assert contract.id == "finding-1"
        assert contract.framework is Framework.ISO_27001
        assert contract.domain is RiskDomain.STORAGE
        assert contract.status is ExternalFindingStatus.FAIL

    def test_payload_has_exactly_the_eleven_contract_fields(self) -> None:
        payload = finding_to_contract(make_finding()).to_payload()
        assert set(payload.keys()) == {
            "id",
            "tenant_id",
            "resource_id",
            "rule_id",
            "framework",
            "control_id",
            "domain",
            "status",
            "severity",
            "evidence",
            "detected_at",
        }

    def test_payload_enum_values_are_the_exact_handoff_strings(self) -> None:
        payload = finding_to_contract(
            make_finding(framework="dnssi", domain="iam", status=FindingStatus.PASS, severity=Severity.LOW)
        ).to_payload()
        assert payload["framework"] == "dnssi"
        assert payload["domain"] == "iam"
        assert payload["status"] == "pass"
        assert payload["severity"] == "low"

    def test_payload_detected_at_is_iso8601_string(self) -> None:
        payload = finding_to_contract(make_finding()).to_payload()
        assert payload["detected_at"] == DETECTED_AT.isoformat()

    def test_internal_only_fields_never_appear_in_payload(self) -> None:
        finding = make_finding(
            scan_id="scan-1",
            rule_version="1.2.3",
            region="us-east-1",
            environment="prod",
            risk=80.0,
            confidence=90.0,
        )
        payload = finding_to_contract(finding).to_payload()
        for internal_field in (
            "risk",
            "confidence",
            "scan_id",
            "rule_version",
            "region",
            "environment",
            "version",
            "superseded_by",
            "related_attack_path_ids",
            "related_drift_event_ids",
        ):
            assert internal_field not in payload

    def test_non_empty_tenant_id_and_resource_id_are_enforced(self) -> None:
        with pytest.raises(Exception):
            FindingContract(
                id="f-1",
                tenant_id="",
                resource_id="r-1",
                rule_id="rule-1",
                framework=Framework.ISO_27001,
                control_id="A.8.24",
                domain=RiskDomain.STORAGE,
                status=ExternalFindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence={},
                detected_at=DETECTED_AT,
            )
        with pytest.raises(Exception):
            FindingContract(
                id="f-1",
                tenant_id="acme",
                resource_id="",
                rule_id="rule-1",
                framework=Framework.ISO_27001,
                control_id="A.8.24",
                domain=RiskDomain.STORAGE,
                status=ExternalFindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence={},
                detected_at=DETECTED_AT,
            )

    def test_detected_at_must_be_timezone_aware(self) -> None:
        with pytest.raises(ContractTranslationError):
            FindingContract(
                id="f-1",
                tenant_id="acme",
                resource_id="r-1",
                rule_id="rule-1",
                framework=Framework.ISO_27001,
                control_id="A.8.24",
                domain=RiskDomain.STORAGE,
                status=ExternalFindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence={},
                detected_at=datetime(2026, 1, 1),
            )


class TestFindingTranslationRejections:
    def test_indeterminate_status_is_rejected(self) -> None:
        with pytest.raises(ContractTranslationError):
            finding_to_contract(make_finding(status=FindingStatus.INDETERMINATE))

    def test_unrecognized_framework_is_rejected(self) -> None:
        with pytest.raises(ContractTranslationError):
            finding_to_contract(make_finding(framework="CIS"))

    def test_unrecognized_domain_is_rejected(self) -> None:
        with pytest.raises(ContractTranslationError):
            finding_to_contract(make_finding(domain="cost_optimization"))

    def test_translation_is_deterministic(self) -> None:
        finding = make_finding()
        payloads = [finding_to_contract(finding).to_payload() for _ in range(20)]
        assert all(payload == payloads[0] for payload in payloads)


class TestExternalFindingStatusHasNoIndeterminate:
    def test_exactly_pass_and_fail(self) -> None:
        assert {s.value for s in ExternalFindingStatus} == {"pass", "fail"}


class TestFrameworkAndRiskDomainVocabulary:
    def test_framework_matches_handoff_exactly(self) -> None:
        assert {f.value for f in Framework} == {
            "iso_27001",
            "loi_05_20",
            "dnssi",
            "nist_csf",
            "soc_2",
        }

    def test_risk_domain_matches_handoff_exactly(self) -> None:
        assert {d.value for d in RiskDomain} == {
            "iam",
            "network",
            "encryption",
            "logging",
            "storage",
        }


class TestNormalizedResourceContractShape:
    def test_valid_resource_translates(self) -> None:
        contract = resource_to_contract(make_resource(), service="s3")
        assert contract.id == "arn:aws:s3:::acme-data"
        assert contract.cloud is CloudProvider.AWS
        assert contract.service == "s3"
        assert contract.type == "s3_bucket"

    def test_payload_has_exactly_the_eight_contract_fields(self) -> None:
        payload = resource_to_contract(make_resource(), service="s3").to_payload()
        assert set(payload.keys()) == {
            "id",
            "tenant_id",
            "cloud",
            "service",
            "region",
            "type",
            "config",
            "collected_at",
        }

    def test_tags_and_relationships_are_absent_from_the_payload(self) -> None:
        payload = resource_to_contract(make_resource(), service="s3").to_payload()
        assert "tags" not in payload
        assert "relationships" not in payload

    def test_cloud_value_matches_handoff_example(self) -> None:
        payload = resource_to_contract(make_resource(), service="s3").to_payload()
        assert payload["cloud"] == "aws"

    def test_service_must_be_supplied_and_non_blank(self) -> None:
        with pytest.raises(ContractTranslationError):
            resource_to_contract(make_resource(), service="")

    def test_collected_at_is_iso8601_string(self) -> None:
        payload = resource_to_contract(make_resource(), service="s3").to_payload()
        assert payload["collected_at"] == DETECTED_AT.isoformat()

    def test_region_may_be_null_for_global_resources(self) -> None:
        resource = make_resource(resource_type="iam_user", region=None)
        payload = resource_to_contract(resource, service="iam").to_payload()
        assert payload["region"] is None

    def test_non_empty_tenant_id_and_id_are_enforced(self) -> None:
        with pytest.raises(Exception):
            NormalizedResourceContract(
                id="",
                tenant_id="acme",
                cloud=CloudProvider.AWS,
                service="s3",
                region="eu-west-1",
                type="s3_bucket",
                config={},
                collected_at=DETECTED_AT,
            )
        with pytest.raises(Exception):
            NormalizedResourceContract(
                id="r-1",
                tenant_id="",
                cloud=CloudProvider.AWS,
                service="s3",
                region="eu-west-1",
                type="s3_bucket",
                config={},
                collected_at=DETECTED_AT,
            )
