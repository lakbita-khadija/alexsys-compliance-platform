"""``YamlScenarioLoader`` — YAML -> ``application.conformance.models.Scenario``
(Phase 3B design proposal, Part L: "tests/conformance/scenarios/*.yaml,
separate from Terraform").

Mirrors ``infrastructure.rules.yaml_rule_catalog.YamlRuleCatalog``'s own
shape and philosophy: this loader's only responsibility is YAML ->
``Scenario`` objects. It never runs a scenario (that's
``application.conformance.runner.RunConformanceScenario``) and never
classifies a comparison (that's ``application.conformance.comparator``)
— a scenario definition that doesn't map cleanly onto ``Scenario``'s
fields fails to load, loudly, rather than being coerced.

Every scenario here is SYNTHETIC: the resource (and any relationship
neighbors) are constructed directly from the YAML, not collected from
real AWS. This is deliberate — it is what makes the conformance suite
runnable in CI with zero AWS credentials, deterministic regardless of
account state, and fast. It validates the RULE CATALOG's behavior
against known resource shapes; validating the AWS COLLECTOR itself
against a real account is the separate, opt-in
``tests/integration/aws`` suite's job (see
``tests/integration/aws/test_scan_terraform_environment.py``'s
``TestPhase3BScenarios`` for the real-AWS equivalent of a handful of
these same rules).

Expected YAML shape (one scenario per file, or a top-level ``scenarios:``
list per file):

    scenario_id: s3-bucket-public
    description: "A publicly exposed bucket fails s3-bucket-public."
    resource:
      resource_id: test-bucket-1
      resource_type: s3_bucket
      tenant_id: conformance-test
      region: us-east-1
      account_id: "123456789012"      # optional
      attributes: {public: true, encrypted: true}
      tags: {}                         # optional, defaults to {}
    relationships:                     # optional, for relationship rules
      - type: attached_to              # a RelationshipType value
        direction: outgoing            # "outgoing" | "incoming"
        target:
          resource_id: sg-1
          resource_type: security_group
          attributes: {has_unrestricted_ingress: true}
    expected_findings:
      - rule_id: s3-bucket-public
        status: fail                   # "pass" | "fail" | "indeterminate"
        severity: critical             # optional
        evidence_contains: ["public"]  # optional
    tags: [s3, exposure]               # optional
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from application.conformance.models import ExpectedFinding, Scenario
from domain.findings.models import FindingStatus
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId
from infrastructure.rules.errors import RuleCatalogError

_SCENARIO_RESOURCE_COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


class YamlScenarioLoader:
    """Loads every ``*.yaml``/``*.yml`` file in a directory into
    ``Scenario`` objects. File order is sorted for deterministic output.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)

    def load(self) -> tuple[Scenario, ...]:
        if not self._directory.is_dir():
            raise RuleCatalogError(f"conformance scenario directory does not exist: {self._directory}")

        scenarios: list[Scenario] = []
        for file_path in sorted(set(self._directory.glob("*.yaml")) | set(self._directory.glob("*.yml"))):
            scenarios.extend(self._load_file(file_path))
        return tuple(scenarios)

    def _load_file(self, file_path: Path) -> list[Scenario]:
        try:
            data = yaml.safe_load(file_path.read_text())
        except yaml.YAMLError as exc:
            raise RuleCatalogError(f"malformed YAML in {file_path.name}: {exc}") from exc

        if data is None:
            return []
        if not isinstance(data, dict):
            raise RuleCatalogError(f"{file_path.name}: top level must be a mapping")

        entries = data["scenarios"] if "scenarios" in data else [data]
        return [self._parse_scenario(entry, file_path) for entry in entries]

    @staticmethod
    def _parse_scenario(entry: dict, file_path: Path) -> Scenario:
        try:
            resource = _parse_resource(entry["resource"])
            resources_by_id: dict[ResourceId, NormalizedResource] = {}
            graph: ResourceGraph | None = None

            relationships = entry.get("relationships")
            if relationships:
                graph = ResourceGraph(tenant_id=resource.tenant_id)
                graph.add_node(GraphNode(resource_id=resource.resource_id, tenant_id=resource.tenant_id, resource_type=resource.resource_type))
                for relationship in relationships:
                    neighbor = _parse_resource(relationship["target"], tenant_id=resource.tenant_id)
                    resources_by_id[neighbor.resource_id] = neighbor
                    graph.add_node(
                        GraphNode(resource_id=neighbor.resource_id, tenant_id=neighbor.tenant_id, resource_type=neighbor.resource_type)
                    )
                    relationship_type = RelationshipType(relationship["type"])
                    direction = relationship.get("direction", "outgoing")
                    if direction not in ("outgoing", "incoming"):
                        raise RuleCatalogError(f"{file_path.name}: relationship direction must be 'outgoing' or 'incoming', got {direction!r}")
                    source_id = resource.resource_id if direction == "outgoing" else neighbor.resource_id
                    target_id = neighbor.resource_id if direction == "outgoing" else resource.resource_id
                    graph.add_edge(GraphEdge(source_id=source_id, target_id=target_id, relationship_type=relationship_type))

            expected_findings = tuple(_parse_expected_finding(e) for e in entry["expected_findings"])

            return Scenario(
                scenario_id=entry["scenario_id"],
                description=entry.get("description", ""),
                resource=resource,
                expected_findings=expected_findings,
                graph=graph,
                resources_by_id=resources_by_id or None,
                tags=tuple(entry.get("tags", ())),
            )
        except KeyError as exc:
            raise RuleCatalogError(f"{file_path.name}: missing required field {exc}") from exc
        except ValueError as exc:
            raise RuleCatalogError(f"{file_path.name}: {exc}") from exc


def _parse_resource(entry: dict, tenant_id: TenantId | None = None) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(entry["resource_id"]),
        resource_type=entry["resource_type"],
        cloud_provider=CloudProvider(entry.get("cloud_provider", "aws")),
        tenant_id=tenant_id or TenantId(entry["tenant_id"]),
        region=entry.get("region"),
        attributes=dict(entry.get("attributes", {})),
        tags=dict(entry.get("tags", {})),
        relationships=(),
        collected_at=_SCENARIO_RESOURCE_COLLECTED_AT,
        account_id=entry.get("account_id"),
    )


def _parse_expected_finding(entry: dict) -> ExpectedFinding:
    severity = Severity(entry["severity"]) if "severity" in entry else None
    return ExpectedFinding(
        rule_id=RuleId(entry["rule_id"]),
        status=FindingStatus(entry["status"]),
        severity=severity,
        evidence_contains=tuple(entry.get("evidence_contains", ())),
    )
