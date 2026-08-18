from datetime import datetime, timezone

import pytest

from application.rules.evaluate_rules import EvaluateRules
from application.rules.rule_catalog import LoadRuleCatalog
from domain.findings.models import FindingStatus
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource
from domain.rules.rule import Remediation, Rule
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import ResourceId, RuleId, TenantId

DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def make_resource(resource_id="bucket-1", tenant_id=TENANT_A, attributes=None):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=(),
        collected_at=DETECTED_AT,
    )


def make_rule(rule_id="rule-1", condition=None):
    return Rule(
        id=RuleId(rule_id),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        severity=Severity.HIGH,
        condition=condition or {"field": "encrypted", "operator": "equals", "value": True},
    )


class FakeRuleCatalog(LoadRuleCatalog):
    def __init__(self, rules):
        self._rules = tuple(rules)

    def load(self):
        return self._rules


class TestEvaluateRules:
    def test_matched_condition_produces_fail_finding(self) -> None:
        # rule requires encrypted == True; resource has encrypted == False -> condition NOT_MATCHED...
        # use a rule whose condition MATCHES an unwanted state to assert MATCHED -> FAIL mapping
        rule = make_rule(condition={"field": "public", "operator": "equals", "value": True})
        resource = make_resource(attributes={"public": True})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert len(findings) == 1
        assert findings[0].status is FindingStatus.FAIL

    def test_not_matched_condition_produces_pass_finding(self) -> None:
        rule = make_rule(condition={"field": "public", "operator": "equals", "value": True})
        resource = make_resource(attributes={"public": False})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert findings[0].status is FindingStatus.PASS

    def test_indeterminate_condition_produces_indeterminate_finding(self) -> None:
        rule = make_rule(condition={"field": "missing_field", "operator": "equals", "value": True})
        resource = make_resource(attributes={})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert findings[0].status is FindingStatus.INDETERMINATE

    def test_indeterminate_is_never_silently_converted(self) -> None:
        rule = make_rule(condition={"field": "missing_field", "operator": "equals", "value": True})
        resource = make_resource(attributes={})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert findings[0].status not in (FindingStatus.PASS, FindingStatus.FAIL)

    def test_every_rule_resource_pair_produces_a_finding(self) -> None:
        rules = [make_rule("rule-1"), make_rule("rule-2")]
        resources = [make_resource("bucket-1"), make_resource("bucket-2")]
        findings = EvaluateRules(FakeRuleCatalog(rules)).evaluate(
            tenant_id=TENANT_A, resources=resources, detected_at=DETECTED_AT
        )
        assert len(findings) == 4  # 2 rules x 2 resources

    def test_finding_preserves_rule_metadata(self) -> None:
        rule = make_rule()
        resource = make_resource(attributes={"encrypted": True})
        finding = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )[0]
        assert finding.rule_id == RuleId("rule-1")
        assert finding.framework == "iso_27001"
        assert finding.control_id == "A.8.24"
        assert finding.domain == "storage"
        assert finding.severity is Severity.HIGH
        assert finding.tenant_id == TENANT_A
        assert finding.resource_id == ResourceId("bucket-1")
        assert finding.detected_at == DETECTED_AT

    def test_finding_id_is_deterministic(self) -> None:
        rule = make_rule()
        resource = make_resource(attributes={"encrypted": True})
        first = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )[0]
        second = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )[0]
        assert first.id == second.id

    def test_empty_resources_produce_no_findings(self) -> None:
        findings = EvaluateRules(FakeRuleCatalog([make_rule()])).evaluate(
            tenant_id=TENANT_A, resources=[], detected_at=DETECTED_AT
        )
        assert findings == ()

    def test_empty_rule_catalog_produces_no_findings(self) -> None:
        findings = EvaluateRules(FakeRuleCatalog([])).evaluate(
            tenant_id=TENANT_A, resources=[make_resource()], detected_at=DETECTED_AT
        )
        assert findings == ()

    def test_foreign_tenant_resource_raises_tenant_isolation_violation(self) -> None:
        rule = make_rule()
        resource = make_resource(tenant_id=TENANT_B)
        with pytest.raises(TenantIsolationViolation):
            EvaluateRules(FakeRuleCatalog([rule])).evaluate(
                tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
            )

    def test_rule_ids_filter_restricts_the_catalog(self) -> None:
        rules = [make_rule("rule-1"), make_rule("rule-2")]
        resource = make_resource("bucket-1")
        findings = EvaluateRules(FakeRuleCatalog(rules)).evaluate(
            tenant_id=TENANT_A,
            resources=[resource],
            detected_at=DETECTED_AT,
            rule_ids=(RuleId("rule-1"),),
        )
        assert len(findings) == 1
        assert findings[0].rule_id == RuleId("rule-1")

    def test_evaluation_is_deterministic_across_runs(self) -> None:
        rules = [make_rule("rule-1"), make_rule("rule-2")]
        resources = [make_resource("bucket-1", attributes={"encrypted": True})]
        catalog = FakeRuleCatalog(rules)
        first = EvaluateRules(catalog).evaluate(tenant_id=TENANT_A, resources=resources, detected_at=DETECTED_AT)
        second = EvaluateRules(catalog).evaluate(tenant_id=TENANT_A, resources=resources, detected_at=DETECTED_AT)
        assert [f.status for f in first] == [f.status for f in second]
        assert [f.id for f in first] == [f.id for f in second]


class TestFindingIdentityAndMetadata:
    def test_logical_finding_id_and_account_id_populated_from_resource(self) -> None:
        rule = make_rule(condition={"field": "public", "operator": "equals", "value": True})
        resource = make_resource("bucket-1", attributes={"public": True})
        resource = NormalizedResource(
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            cloud_provider=resource.cloud_provider,
            tenant_id=resource.tenant_id,
            region=resource.region,
            attributes=resource.attributes,
            tags=resource.tags,
            relationships=resource.relationships,
            collected_at=resource.collected_at,
            account_id="123456789012",
        )
        finding = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT, scan_id="scan-1"
        )[0]
        assert finding.account_id == "123456789012"
        assert finding.logical_finding_id == f"{TENANT_A!s}:123456789012:bucket-1:rule-1"
        assert str(finding.id) == f"{finding.logical_finding_id}:scan-1"

    def test_logical_finding_id_stable_across_scans_finding_id_is_not(self) -> None:
        rule = make_rule(condition={"field": "public", "operator": "equals", "value": True})
        resource = make_resource("bucket-1", attributes={"public": True})
        first = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT, scan_id="scan-1"
        )[0]
        second = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT, scan_id="scan-2"
        )[0]
        assert first.logical_finding_id == second.logical_finding_id
        assert first.id != second.id

    def test_rule_version_populates_finding_rule_version(self) -> None:
        rule = Rule(
            id=RuleId("rule-1"),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            severity=Severity.HIGH,
            condition={"field": "encrypted", "operator": "equals", "value": True},
            version="2.3.1",
        )
        resource = make_resource(attributes={"encrypted": True})
        finding = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )[0]
        assert finding.rule_version == "2.3.1"

    def test_evidence_template_renders_narrative_into_finding_evidence(self) -> None:
        rule = Rule(
            id=RuleId("rule-1"),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            severity=Severity.HIGH,
            condition={"field": "public", "operator": "equals", "value": True},
            evidence_template="Bucket {resource_id} is public.",
            remediation=Remediation(
                summary="Block public access.",
                why_it_matters="Public buckets can leak data.",
                how_to_fix="Enable S3 Block Public Access.",
            ),
        )
        resource = make_resource("bucket-1", attributes={"public": True})
        finding = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )[0]
        assert finding.evidence.data["narrative"] == "Bucket bucket-1 is public."
        assert finding.evidence.data["public"] is True


class TestGraphAwareEvaluation:
    def test_relationship_condition_fires_using_threaded_graph(self) -> None:
        sg = NormalizedResource(
            resource_id=ResourceId("sg-1"),
            resource_type="security_group",
            cloud_provider=CloudProvider.AWS,
            tenant_id=TENANT_A,
            region="us-east-1",
            attributes={},
            tags={},
            relationships=(),
            collected_at=DETECTED_AT,
        )
        instance = NormalizedResource(
            resource_id=ResourceId("i-1"),
            resource_type="ec2_instance",
            cloud_provider=CloudProvider.AWS,
            tenant_id=TENANT_A,
            region="us-east-1",
            attributes={"public_ip": "203.0.113.5"},
            tags={},
            relationships=(),
            collected_at=DETECTED_AT,
        )

        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(GraphNode(resource_id=sg.resource_id, tenant_id=TENANT_A, resource_type="security_group"))
        graph.add_node(GraphNode(resource_id=instance.resource_id, tenant_id=TENANT_A, resource_type="ec2_instance"))
        graph.add_edge(
            GraphEdge(
                source_id=sg.resource_id,
                target_id=instance.resource_id,
                relationship_type=RelationshipType.ATTACHED_TO,
            )
        )

        rule = make_rule(
            condition={
                "relationship": RelationshipType.ATTACHED_TO.value,
                "direction": "outgoing",
                "target_type": "ec2_instance",
                "where": {"field": "public_ip", "operator": "exists"},
            }
        )

        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[sg, instance], detected_at=DETECTED_AT, graph=graph
        )
        sg_finding = next(f for f in findings if f.resource_id == sg.resource_id)
        assert sg_finding.status is FindingStatus.FAIL

    def test_relationship_condition_without_graph_is_indeterminate_wiring_error_not_silent(self) -> None:
        rule = make_rule(
            condition={
                "relationship": RelationshipType.ATTACHED_TO.value,
                "direction": "outgoing",
                "where": {"field": "public_ip", "operator": "exists"},
            }
        )
        resource = make_resource()
        with pytest.raises(Exception):
            EvaluateRules(FakeRuleCatalog([rule])).evaluate(
                tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
            )


class TestResourceTypeScoping:
    """A rule scoped to another resource type produces NO finding —
    deliberately different from INDETERMINATE. See
    `Rule.applies_to_resource_type`.
    """

    @staticmethod
    def _rule(rule_id: str, resource_type: str | None):
        return Rule(
            id=RuleId(rule_id),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            severity=Severity.HIGH,
            condition={"field": "public", "operator": "equals", "value": True},
            applies_to_resource_type=resource_type,
        )

    def test_rule_scoped_to_another_type_produces_no_finding(self) -> None:
        rule = self._rule("kv-rule", "azure_key_vault")
        resource = make_resource("bucket-1", attributes={"public": True})  # an s3_bucket
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert findings == ()

    def test_rule_scoped_to_the_matching_type_produces_a_finding(self) -> None:
        rule = self._rule("s3-rule", "s3_bucket")
        resource = make_resource("bucket-1", attributes={"public": True})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert len(findings) == 1
        assert findings[0].status is FindingStatus.FAIL

    def test_unscoped_rule_still_applies_to_every_type(self) -> None:
        rule = self._rule("legacy-rule", None)
        resource = make_resource("bucket-1", attributes={"public": True})
        findings = EvaluateRules(FakeRuleCatalog([rule])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert len(findings) == 1

    def test_skipped_rule_is_not_reported_as_indeterminate(self) -> None:
        # The distinction that matters: "this rule is not about this
        # resource type" must not be buried among genuine
        # missing-data INDETERMINATEs.
        scoped_away = self._rule("kv-rule", "azure_key_vault")
        applicable = self._rule("s3-rule", "s3_bucket")
        resource = make_resource("bucket-1", attributes={"public": True})
        findings = EvaluateRules(FakeRuleCatalog([scoped_away, applicable])).evaluate(
            tenant_id=TENANT_A, resources=[resource], detected_at=DETECTED_AT
        )
        assert [str(f.rule_id) for f in findings] == ["s3-rule"]
        assert all(f.status is not FindingStatus.INDETERMINATE for f in findings)

    def test_mixed_provider_scan_only_evaluates_matching_rules(self) -> None:
        aws_rule = self._rule("s3-rule", "s3_bucket")
        azure_rule = self._rule("azure-rule", "azure_storage_account")

        aws_resource = make_resource("bucket-1", attributes={"public": True})
        azure_resource = NormalizedResource(
            resource_id=ResourceId("azure-store-1"),
            resource_type="azure_storage_account",
            cloud_provider=CloudProvider.AZURE,
            tenant_id=TENANT_A,
            region="westeurope",
            attributes={"public": True},
            tags={},
            relationships=(),
            collected_at=DETECTED_AT,
        )

        findings = EvaluateRules(FakeRuleCatalog([aws_rule, azure_rule])).evaluate(
            tenant_id=TENANT_A, resources=[aws_resource, azure_resource], detected_at=DETECTED_AT
        )
        by_resource = {str(f.resource_id): str(f.rule_id) for f in findings}
        assert by_resource == {"bucket-1": "s3-rule", "azure-store-1": "azure-rule"}
