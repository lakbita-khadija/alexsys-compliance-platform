"""``RunConformanceScenario`` — glues a ``Scenario`` to the real rule
engine and the comparator (Phase 3B design proposal, Part K).

This is intentionally the thinnest possible piece of orchestration: it
does not evaluate any rule itself (that's
``application.rules.evaluate_rules.EvaluateRules``, reused unmodified)
and it does not classify any comparison itself (that's
``comparator.ConformanceComparator``, also reused unmodified). Its only
job is running the full loaded rule catalog against a scenario's
resource, projecting the resulting ``Finding``s down to
comparison-relevant ``ActualFinding``s, and handing both to the
comparator.

The full catalog is run — never restricted to just the rule_ids a
scenario's expectations mention — specifically so ``UNEXPECTED_FINDING``
(Part K) can be detected: a rule nobody predicted would fire against
this resource is exactly the kind of surprise a conformance framework
exists to catch, and restricting to only the expected rule_ids would
make that outcome permanently unreachable.

A graph is ALWAYS supplied to the rule engine, even when a scenario
declares no relationships — in that case an otherwise-empty graph
containing only the scenario's own resource. This matters because the
full catalog is run: ``domain.rules.conditions`` treats a
``relationship`` condition evaluated without a graph as a *caller
wiring bug* and raises (correctly — in the real scan path
``ScanCloudAccount`` always builds one). Supplying an empty graph gives
the semantically right answer instead: ``ResourceGraph.neighbors()``
returns ``()``, which existence-quantifies to ``NOT_MATCHED`` -> PASS.
"A bucket with no attached security group does not fail
'attached to an open security group'" is a determinate fact, not a
missing-data case.

``detected_at`` is a fixed, module-level constant rather than
``datetime.now()`` — conformance runs must be deterministic regardless
of wall-clock time (the same invariant enforced everywhere else in this
codebase; see domain.drift.diff_engine.DiffEngine and
domain.rules.conditions's temporal operators for the same principle).
"""

from __future__ import annotations

from datetime import datetime, timezone

from application.conformance.comparator import ConformanceComparator
from application.conformance.models import ActualFinding, ConformanceReport, Scenario
from application.rules.evaluate_rules import EvaluateRules
from application.rules.rule_catalog import LoadRuleCatalog
from domain.graph.models import GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource
from domain.shared.identifiers import ResourceId

CONFORMANCE_DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


class RunConformanceScenario:
    """Runs one ``Scenario`` against a rule catalog and returns its
    ``ConformanceReport``.
    """

    def __init__(self, rule_catalog: LoadRuleCatalog, comparator: ConformanceComparator | None = None) -> None:
        self._rule_catalog = rule_catalog
        self._comparator = comparator or ConformanceComparator()

    def run(self, scenario: Scenario) -> ConformanceReport:
        resources = self._resolve_resources(scenario)
        graph = scenario.graph if scenario.graph is not None else self._empty_graph(scenario)

        findings = EvaluateRules(self._rule_catalog).evaluate(
            tenant_id=scenario.resource.tenant_id,
            resources=resources,
            detected_at=CONFORMANCE_DETECTED_AT,
            graph=graph,
        )

        actual_findings = tuple(
            ActualFinding(
                rule_id=f.rule_id,
                resource_id=f.resource_id,
                status=f.status,
                severity=f.severity,
                evidence=f.evidence.data,
            )
            for f in findings
            if f.resource_id == scenario.resource.resource_id
        )

        return self._comparator.compare(scenario, actual_findings)

    @staticmethod
    def _resolve_resources(scenario: Scenario) -> tuple[NormalizedResource, ...]:
        by_id: dict[ResourceId, NormalizedResource] = {scenario.resource.resource_id: scenario.resource}
        if scenario.resources_by_id:
            by_id.update(scenario.resources_by_id)
        return tuple(by_id.values())

    @staticmethod
    def _empty_graph(scenario: Scenario) -> ResourceGraph:
        """A graph containing only the scenario's own resource and no
        edges — see the module docstring for why this is supplied
        rather than passing ``None``.
        """

        graph = ResourceGraph(tenant_id=scenario.resource.tenant_id)
        graph.add_node(
            GraphNode(
                resource_id=scenario.resource.resource_id,
                tenant_id=scenario.resource.tenant_id,
                resource_type=scenario.resource.resource_type,
            )
        )
        return graph
