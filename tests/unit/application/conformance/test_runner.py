from datetime import datetime, timezone

from application.conformance.models import ConformanceOutcome, ExpectedFinding, Scenario
from application.conformance.runner import RunConformanceScenario
from application.rules.rule_catalog import LoadRuleCatalog
from domain.findings.models import FindingStatus
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource
from domain.rules.rule import Rule
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT = TenantId("acme")


class FakeRuleCatalog(LoadRuleCatalog):
    def __init__(self, rules):
        self._rules = tuple(rules)

    def load(self):
        return self._rules


def make_resource(resource_id="bucket-1", resource_type="s3_bucket", attributes=None) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=(),
        collected_at=COLLECTED_AT,
    )


def make_rule(rule_id, condition, severity=Severity.HIGH) -> Rule:
    return Rule(
        id=RuleId(rule_id),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        severity=severity,
        condition=condition,
    )


class TestRunConformanceScenarioBasics:
    def test_matching_rule_produces_a_pass_report(self) -> None:
        rule = make_rule("s3-public", {"field": "public", "operator": "equals", "value": True})
        catalog = FakeRuleCatalog([rule])
        scenario = Scenario(
            scenario_id="public-bucket",
            description="a public bucket",
            resource=make_resource(attributes={"public": True}),
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-public"), status=FindingStatus.FAIL),),
        )
        report = RunConformanceScenario(catalog).run(scenario)
        assert report.is_fully_conformant is True
        assert report.results[0].outcome is ConformanceOutcome.PASS

    def test_full_catalog_is_run_not_just_expected_rule_ids(self) -> None:
        expected_rule = make_rule("s3-public", {"field": "public", "operator": "equals", "value": True})
        surprise_rule = make_rule("s3-not-encrypted", {"field": "encrypted", "operator": "equals", "value": False})
        catalog = FakeRuleCatalog([expected_rule, surprise_rule])
        scenario = Scenario(
            scenario_id="public-bucket",
            description="a public bucket that is also unencrypted, unexpectedly",
            resource=make_resource(attributes={"public": True, "encrypted": False}),
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-public"), status=FindingStatus.FAIL),),
        )
        report = RunConformanceScenario(catalog).run(scenario)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("s3-public")] is ConformanceOutcome.PASS
        assert outcomes[RuleId("s3-not-encrypted")] is ConformanceOutcome.UNEXPECTED_FINDING

    def test_missing_finding_when_expected_rule_id_is_not_in_the_catalog(self) -> None:
        catalog = FakeRuleCatalog([])
        scenario = Scenario(
            scenario_id="public-bucket",
            description="x",
            resource=make_resource(),
            expected_findings=(ExpectedFinding(rule_id=RuleId("nonexistent-rule"), status=FindingStatus.FAIL),),
        )
        report = RunConformanceScenario(catalog).run(scenario)
        assert report.results[0].outcome is ConformanceOutcome.MISSING_FINDING

    def test_run_is_deterministic_across_calls(self) -> None:
        rule = make_rule("s3-public", {"field": "public", "operator": "equals", "value": True})
        catalog = FakeRuleCatalog([rule])
        scenario = Scenario(
            scenario_id="public-bucket",
            description="x",
            resource=make_resource(attributes={"public": True}),
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-public"), status=FindingStatus.FAIL),),
        )
        runner = RunConformanceScenario(catalog)
        first = runner.run(scenario)
        second = runner.run(scenario)
        assert first.results == second.results


class TestRunConformanceScenarioWithGraph:
    def test_relationship_rule_resolves_using_scenario_graph_and_resources_by_id(self) -> None:
        sg = make_resource(resource_id="sg-1", resource_type="security_group", attributes={"has_unrestricted_ingress": True})
        instance = make_resource(resource_id="i-1", resource_type="ec2_instance")

        graph = ResourceGraph(tenant_id=TENANT)
        graph.add_node(GraphNode(resource_id=instance.resource_id, tenant_id=TENANT, resource_type="ec2_instance"))
        graph.add_node(GraphNode(resource_id=sg.resource_id, tenant_id=TENANT, resource_type="security_group"))
        graph.add_edge(
            GraphEdge(source_id=instance.resource_id, target_id=sg.resource_id, relationship_type=RelationshipType.ATTACHED_TO)
        )

        rule = make_rule(
            "ec2-open-sg",
            {
                "relationship": "attached_to",
                "direction": "outgoing",
                "where": {"field": "has_unrestricted_ingress", "operator": "equals", "value": True},
            },
        )
        catalog = FakeRuleCatalog([rule])
        scenario = Scenario(
            scenario_id="ec2-attached-to-open-sg",
            description="an ec2 instance attached to an open security group",
            resource=instance,
            expected_findings=(ExpectedFinding(rule_id=RuleId("ec2-open-sg"), status=FindingStatus.FAIL),),
            graph=graph,
            resources_by_id={sg.resource_id: sg},
        )
        report = RunConformanceScenario(catalog).run(scenario)
        assert report.is_fully_conformant is True

    def test_only_the_scenarios_own_resource_findings_are_compared(self) -> None:
        # The neighbor resource (sg) is included in resources_by_id so
        # relationship resolution works, but its own findings must not
        # leak into this scenario's report — only findings for
        # scenario.resource (the ec2 instance) should appear.
        sg = make_resource(resource_id="sg-1", resource_type="security_group", attributes={"has_unrestricted_ingress": True})
        instance = make_resource(resource_id="i-1", resource_type="ec2_instance")

        graph = ResourceGraph(tenant_id=TENANT)
        graph.add_node(GraphNode(resource_id=instance.resource_id, tenant_id=TENANT, resource_type="ec2_instance"))
        graph.add_node(GraphNode(resource_id=sg.resource_id, tenant_id=TENANT, resource_type="security_group"))
        graph.add_edge(
            GraphEdge(source_id=instance.resource_id, target_id=sg.resource_id, relationship_type=RelationshipType.ATTACHED_TO)
        )

        sg_rule = make_rule("sg-open", {"field": "has_unrestricted_ingress", "operator": "equals", "value": True})
        catalog = FakeRuleCatalog([sg_rule])
        scenario = Scenario(
            scenario_id="ec2-scenario",
            description="x",
            resource=instance,
            expected_findings=(ExpectedFinding(rule_id=RuleId("sg-open"), status=FindingStatus.FAIL),),
            graph=graph,
            resources_by_id={sg.resource_id: sg},
        )
        report = RunConformanceScenario(catalog).run(scenario)
        # sg-open never fires against the ec2 instance (field absent there) -> MISSING/INDETERMINATE, never PASS via leakage
        assert report.results[0].outcome is not ConformanceOutcome.PASS
