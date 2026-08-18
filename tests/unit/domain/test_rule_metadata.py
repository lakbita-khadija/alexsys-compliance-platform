from datetime import datetime, timezone

import pytest

from domain.graph.models import ResourceGraph
from domain.resources.models import NormalizedResource
from domain.rules.conditions import EvaluationResult
from domain.rules.rule import FrameworkMapping, Remediation, Rule
from domain.shared.enums import CloudProvider, Confidence, Severity
from domain.shared.errors import InvalidRule
from domain.shared.identifiers import ResourceId, RuleId, TenantId


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
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def minimal_rule(**overrides) -> Rule:
    defaults = dict(
        id=RuleId("rule-1"),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        severity=Severity.CRITICAL,
        condition={"field": "public", "operator": "equals", "value": True},
    )
    defaults.update(overrides)
    return Rule(**defaults)


class TestBackwardCompatibleConstruction:
    def test_rule_still_constructs_with_only_the_original_six_fields(self) -> None:
        rule = minimal_rule()
        assert rule.version == "1.0.0"
        assert rule.title == ""
        assert rule.confidence is Confidence.HIGH
        assert rule.remediation is None
        assert rule.framework_mappings == ()

    def test_evaluate_still_works_with_no_new_params(self) -> None:
        rule = minimal_rule()
        assert rule.evaluate(make_resource()) is EvaluationResult.MATCHED


class TestFrameworkMapping:
    def test_valid_mapping_defaults_to_unresolved(self) -> None:
        mapping = FrameworkMapping(framework="ISO27001", control="A.8.24")
        assert mapping.status == "unresolved"

    def test_verified_status_accepted(self) -> None:
        mapping = FrameworkMapping(
            framework="CIS_AWS",
            control="5.2",
            status="verified",
            # STEP 7: a verified mapping must say what it was
            # verified against. The fixture now exercises the real
            # contract instead of a shape the loader would reject.
            provenance="CIS AWS Foundations Benchmark v1.5.0, section 5.2",
        )
        assert mapping.status == "verified"

    def test_invalid_status_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            FrameworkMapping(framework="CIS_AWS", control="5.2", status="probably")

    def test_blank_framework_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            FrameworkMapping(framework="  ", control="5.2")


class TestRemediation:
    def test_valid_remediation(self) -> None:
        remediation = Remediation(
            summary="Bucket is public",
            why_it_matters="Public buckets can leak sensitive data",
            how_to_fix="Enable block public access",
        )
        assert remediation.automation_example is None

    def test_blank_field_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            Remediation(summary="", why_it_matters="x", how_to_fix="y")


class TestRuleWithFullMetadata:
    def test_rule_carries_full_catalog_metadata(self) -> None:
        rule = minimal_rule(
            version="2.0.0",
            title="S3 bucket must not be publicly accessible",
            description="Detects buckets exposed via public ACL grants.",
            service="s3",
            confidence=Confidence.HIGH,
            rationale="Public buckets are a leading cause of cloud data breaches.",
            evidence_template="Bucket {resource_id} is public.",
            remediation=Remediation(
                summary="Bucket is public",
                why_it_matters="Data exposure risk",
                how_to_fix="aws s3api put-public-access-block ...",
            ),
            references=("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",),
            tags=("s3", "public-exposure"),
            framework_mappings=(
                FrameworkMapping(
                    framework="CIS_AWS",
                    control="2.1.5",
                    status="verified",
                    provenance="CIS AWS Foundations Benchmark v1.5.0, section 2.1.5",
                ),
            ),
        )
        assert rule.title.startswith("S3 bucket")
        assert rule.framework_mappings[0].status == "verified"
        assert "s3" in rule.tags

    def test_invalid_confidence_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            minimal_rule(confidence="very-high")  # type: ignore[arg-type]

    def test_invalid_remediation_type_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            minimal_rule(remediation="just fix it")  # type: ignore[arg-type]

    def test_invalid_framework_mappings_entry_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            minimal_rule(framework_mappings=({"framework": "x", "control": "y"},))  # type: ignore[arg-type]


class TestRuleEvaluateAcceptsGraphContext:
    def test_evaluate_accepts_graph_and_resources_by_id_kwargs(self) -> None:
        rule = minimal_rule()
        graph = ResourceGraph(tenant_id=TenantId("acme"))
        result = rule.evaluate(make_resource(), graph=graph, resources_by_id={})
        assert result is EvaluationResult.MATCHED


class TestAppliesToResourceType:
    """Resource-type scoping (Phase 3B, multi-cloud).

    Attribute names are not globally unique across resource types — an
    Azure Key Vault and an Azure storage account both carry
    `network_default_action` — so a rule must be able to declare which
    resource type it is about.
    """

    @staticmethod
    def _resource(resource_type: str) -> NormalizedResource:
        return NormalizedResource(
            resource_id=ResourceId("r-1"),
            resource_type=resource_type,
            cloud_provider=CloudProvider.AWS,
            tenant_id=TenantId("acme"),
            region="us-east-1",
            attributes={"public": True},
            tags={},
            relationships=(),
            collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_defaults_to_none_meaning_every_resource_type(self) -> None:
        rule = minimal_rule()
        assert rule.applies_to_resource_type is None
        assert rule.applies_to(self._resource("s3_bucket")) is True
        assert rule.applies_to(self._resource("azure_key_vault")) is True

    def test_matching_resource_type_applies(self) -> None:
        rule = minimal_rule(applies_to_resource_type="s3_bucket")
        assert rule.applies_to(self._resource("s3_bucket")) is True

    def test_non_matching_resource_type_does_not_apply(self) -> None:
        rule = minimal_rule(applies_to_resource_type="s3_bucket")
        assert rule.applies_to(self._resource("azure_key_vault")) is False

    def test_blank_resource_type_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            minimal_rule(applies_to_resource_type="   ")

    def test_scoping_does_not_affect_evaluate_itself(self) -> None:
        # `applies_to` is a separate question from `evaluate`: the
        # caller decides whether to evaluate, and Rule.evaluate never
        # silently no-ops based on resource type.
        rule = minimal_rule(
            applies_to_resource_type="s3_bucket",
            condition={"field": "public", "operator": "equals", "value": True},
        )
        assert rule.evaluate(self._resource("azure_key_vault")) is EvaluationResult.MATCHED
