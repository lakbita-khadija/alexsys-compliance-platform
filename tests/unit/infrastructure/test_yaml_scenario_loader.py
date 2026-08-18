import pytest

from domain.findings.models import FindingStatus
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId
from infrastructure.conformance.scenario_loader import YamlScenarioLoader
from infrastructure.rules.errors import RuleCatalogError

MINIMAL_SCENARIO = """
scenario_id: s3-public
description: a public bucket
resource:
  resource_id: bucket-1
  resource_type: s3_bucket
  tenant_id: conformance-test
  region: us-east-1
  attributes:
    public: true
expected_findings:
  - rule_id: s3-bucket-public
    status: fail
"""

FULL_SCENARIO = """
scenario_id: s3-public-full
description: a public bucket with every optional field set
resource:
  resource_id: bucket-2
  resource_type: s3_bucket
  tenant_id: conformance-test
  region: eu-west-1
  account_id: "123456789012"
  attributes:
    public: true
  tags:
    env: test
expected_findings:
  - rule_id: s3-bucket-public
    status: fail
    severity: critical
    evidence_contains: ["bucket-2", "public"]
tags: [s3, exposure]
"""

RELATIONSHIP_SCENARIO = """
scenario_id: ec2-open-sg
description: an instance attached to an open security group
resource:
  resource_id: i-1
  resource_type: ec2_instance
  tenant_id: conformance-test
  region: us-east-1
  attributes: {}
relationships:
  - type: attached_to
    direction: outgoing
    target:
      resource_id: sg-1
      resource_type: security_group
      attributes:
        has_unrestricted_ingress: true
expected_findings:
  - rule_id: ec2-instance-attached-to-open-security-group
    status: fail
"""

MULTI_SCENARIO_FILE = """
scenarios:
  - scenario_id: first
    description: x
    resource:
      resource_id: bucket-a
      resource_type: s3_bucket
      tenant_id: conformance-test
      attributes: {}
    expected_findings:
      - rule_id: rule-1
        status: pass
  - scenario_id: second
    description: y
    resource:
      resource_id: bucket-b
      resource_type: s3_bucket
      tenant_id: conformance-test
      attributes: {}
    expected_findings:
      - rule_id: rule-2
        status: pass
"""


class TestYamlScenarioLoaderValidLoading:
    def test_loads_a_minimal_scenario(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(MINIMAL_SCENARIO)
        scenarios = YamlScenarioLoader(tmp_path).load()
        assert len(scenarios) == 1
        scenario = scenarios[0]
        assert scenario.scenario_id == "s3-public"
        assert scenario.resource.resource_id == ResourceId("bucket-1")
        assert scenario.resource.tenant_id == TenantId("conformance-test")
        assert scenario.resource.cloud_provider is CloudProvider.AWS
        assert scenario.expected_findings[0].rule_id == RuleId("s3-bucket-public")
        assert scenario.expected_findings[0].status is FindingStatus.FAIL

    def test_optional_expectation_fields_default_to_none_and_empty(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(MINIMAL_SCENARIO)
        expected = YamlScenarioLoader(tmp_path).load()[0].expected_findings[0]
        assert expected.severity is None
        assert expected.evidence_contains == ()

    def test_loads_every_optional_field(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(FULL_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        assert scenario.resource.account_id == "123456789012"
        assert scenario.resource.region == "eu-west-1"
        assert scenario.resource.tags == {"env": "test"}
        assert scenario.tags == ("s3", "exposure")
        assert scenario.expected_findings[0].severity is Severity.CRITICAL
        assert scenario.expected_findings[0].evidence_contains == ("bucket-2", "public")

    def test_scenario_without_relationships_has_no_graph(self, tmp_path) -> None:
        (tmp_path / "s3.yaml").write_text(MINIMAL_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        assert scenario.graph is None
        assert scenario.resources_by_id is None

    def test_multiple_scenarios_in_one_file(self, tmp_path) -> None:
        (tmp_path / "many.yaml").write_text(MULTI_SCENARIO_FILE)
        scenarios = YamlScenarioLoader(tmp_path).load()
        assert [s.scenario_id for s in scenarios] == ["first", "second"]

    def test_empty_directory_yields_nothing(self, tmp_path) -> None:
        assert YamlScenarioLoader(tmp_path).load() == ()

    def test_loading_is_deterministic(self, tmp_path) -> None:
        (tmp_path / "a.yaml").write_text(MINIMAL_SCENARIO)
        (tmp_path / "b.yaml").write_text(FULL_SCENARIO)
        first = YamlScenarioLoader(tmp_path).load()
        second = YamlScenarioLoader(tmp_path).load()
        assert [s.scenario_id for s in first] == [s.scenario_id for s in second]


class TestYamlScenarioLoaderRelationships:
    def test_relationship_builds_a_graph_with_both_nodes(self, tmp_path) -> None:
        (tmp_path / "ec2.yaml").write_text(RELATIONSHIP_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        assert scenario.graph is not None
        assert scenario.graph.has_node(ResourceId("i-1"))
        assert scenario.graph.has_node(ResourceId("sg-1"))

    def test_relationship_edge_has_the_declared_type_and_direction(self, tmp_path) -> None:
        (tmp_path / "ec2.yaml").write_text(RELATIONSHIP_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        edge = scenario.graph.edges[0]
        assert edge.source_id == ResourceId("i-1")
        assert edge.target_id == ResourceId("sg-1")
        assert edge.relationship_type is RelationshipType.ATTACHED_TO

    def test_incoming_direction_reverses_the_edge(self, tmp_path) -> None:
        (tmp_path / "ec2.yaml").write_text(RELATIONSHIP_SCENARIO.replace("direction: outgoing", "direction: incoming"))
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        edge = scenario.graph.edges[0]
        assert edge.source_id == ResourceId("sg-1")
        assert edge.target_id == ResourceId("i-1")

    def test_neighbor_full_resource_is_available_for_evaluation(self, tmp_path) -> None:
        (tmp_path / "ec2.yaml").write_text(RELATIONSHIP_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        neighbor = scenario.resources_by_id[ResourceId("sg-1")]
        assert neighbor.attributes["has_unrestricted_ingress"] is True

    def test_neighbor_inherits_the_scenario_resources_tenant(self, tmp_path) -> None:
        (tmp_path / "ec2.yaml").write_text(RELATIONSHIP_SCENARIO)
        scenario = YamlScenarioLoader(tmp_path).load()[0]
        neighbor = scenario.resources_by_id[ResourceId("sg-1")]
        assert neighbor.tenant_id == scenario.resource.tenant_id


class TestYamlScenarioLoaderInvalidInput:
    def test_nonexistent_directory_fails_clearly(self) -> None:
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader("/no/such/directory").load()

    def test_malformed_yaml_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "broken.yaml").write_text("scenario_id: [unclosed\n")
        with pytest.raises(RuleCatalogError, match="broken.yaml"):
            YamlScenarioLoader(tmp_path).load()

    def test_missing_required_field_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text("scenario_id: x\ndescription: y\n")
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader(tmp_path).load()

    def test_scenario_with_no_expectations_is_rejected(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(
            """
scenario_id: x
description: y
resource:
  resource_id: bucket-1
  resource_type: s3_bucket
  tenant_id: conformance-test
  attributes: {}
expected_findings: []
"""
        )
        with pytest.raises(Exception):
            YamlScenarioLoader(tmp_path).load()

    def test_unknown_relationship_type_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(RELATIONSHIP_SCENARIO.replace("type: attached_to", "type: teleports_to"))
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader(tmp_path).load()

    def test_invalid_direction_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(RELATIONSHIP_SCENARIO.replace("direction: outgoing", "direction: sideways"))
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader(tmp_path).load()

    def test_unknown_status_value_fails_clearly(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text(MINIMAL_SCENARIO.replace("status: fail", "status: maybe"))
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader(tmp_path).load()

    def test_top_level_must_be_a_mapping(self, tmp_path) -> None:
        (tmp_path / "bad.yaml").write_text("- just\n- a\n- list\n")
        with pytest.raises(RuleCatalogError):
            YamlScenarioLoader(tmp_path).load()


class TestScenarioLoaderDoesNotEvaluateRules:
    def test_loader_never_imports_the_rule_engine(self) -> None:
        import ast
        import inspect

        import infrastructure.conformance.scenario_loader as loader_module

        tree = ast.parse(inspect.getsource(loader_module))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert "domain.rules.conditions" not in imported
        assert "application.rules.evaluate_rules" not in imported
