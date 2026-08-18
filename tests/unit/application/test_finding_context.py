"""Tests for finding contextualization (graph expansion §3).

The defect being fixed: a cross-resource finding said *"EC2 instance
attached to an open security group"* without naming **which** security
group. The rule walked the edge, decided, and discarded the traversal —
throwing away the one fact a responder needs.

The risk in fixing it is naming the wrong resources. A finding that lists
resources it did not actually consider is worse than one that lists none,
because someone will go investigate them. So most of these tests are
about what does **not** appear in ``related_resources``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.rules.evaluate_rules import EvaluateRules
from application.rules.rule_catalog import LoadRuleCatalog
from application.graph.build_resource_graph import BuildResourceGraph
from domain.findings.models import Finding, FindingStatus
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.rule import Rule
from domain.rules.trace import RelationshipObservation, RelationshipTrace
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def resource(resource_id, resource_type, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
    )


def rule(rule_id, condition):
    return Rule(
        id=RuleId(rule_id),
        framework="iso_27001",
        control_id="A.8.20",
        domain="network",
        severity=Severity.HIGH,
        condition=condition,
        applies_to_resource_type="ec2_instance",
    )


class StubCatalog(LoadRuleCatalog):
    def __init__(self, rules):
        self._rules = tuple(rules)

    def load(self):
        return self._rules


ATTACHED_TO_OPEN_SG = {
    "relationship": "attached_to",
    "direction": "outgoing",
    "target_type": "security_group",
    "where": {"field": "unrestricted_ingress", "operator": "is_true"},
}


def scan(rules, resources):
    """Run the real use case over a real graph — no fakes at the seam.

    Every defect this codebase has found late was at a seam that only
    fakes had exercised, so this builds the graph the way a scan does.
    """

    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    findings = EvaluateRules(rule_catalog=StubCatalog(rules)).evaluate(
        tenant_id=TENANT,
        resources=resources,
        detected_at=NOW,
        graph=graph,
    )
    return {str(f.rule_id): f for f in findings if f.resource_id == ResourceId("i-web")}


def exposure_estate():
    """One instance, two security groups — only one of them open."""

    return [
        resource(
            "i-web",
            "ec2_instance",
            attributes={"public_ip": "1.2.3.4"},
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("sg-open"),
                    relationship_type=RelationshipType.ATTACHED_TO,
                ),
                ResourceRelationship(
                    target_resource_id=ResourceId("sg-closed"),
                    relationship_type=RelationshipType.ATTACHED_TO,
                ),
            ),
        ),
        resource("sg-open", "security_group", attributes={"unrestricted_ingress": True}),
        resource("sg-closed", "security_group", attributes={"unrestricted_ingress": False}),
    ]


class TestRelatedResources:
    def test_a_cross_resource_finding_names_the_resource_it_matched(self) -> None:
        findings = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate())
        finding = findings["open-sg"]
        assert finding.status is FindingStatus.FAIL
        assert finding.related_resources == ("sg-open",)

    def test_the_non_matching_neighbour_is_not_named(self) -> None:
        # sg-closed was traversed and examined. It is not related to the
        # finding — naming it would send a responder to a compliant
        # resource.
        assert "sg-closed" not in scan(
            [rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate()
        )["open-sg"].related_resources

    def test_a_single_resource_rule_relates_to_nothing(self) -> None:
        single = rule("public-ip", {"field": "public_ip", "operator": "exists"})
        finding = scan([single], exposure_estate())["public-ip"]
        assert finding.status is FindingStatus.FAIL
        assert finding.related_resources == ()
        assert finding.graph_context is None

    def test_related_resources_are_sorted_and_deduplicated(self) -> None:
        estate = exposure_estate()
        estate[2] = resource("sg-closed", "security_group", {"unrestricted_ingress": True})
        # Both groups now match, and the rule appears twice in the tree
        # so each neighbour is observed twice.
        both = rule("open-sg", {"or": [ATTACHED_TO_OPEN_SG, ATTACHED_TO_OPEN_SG]})
        assert scan([both], estate)["open-sg"].related_resources == ("sg-closed", "sg-open")

    def test_a_passing_cross_resource_rule_still_reports_context(self) -> None:
        estate = exposure_estate()
        estate[1] = resource("sg-open", "security_group", {"unrestricted_ingress": False})
        finding = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], estate)["open-sg"]
        assert finding.status is FindingStatus.PASS
        # Nothing matched, so nothing is related — but the neighbourhood
        # is still attached, because the rule DID look.
        assert finding.related_resources == ()
        assert finding.graph_context is not None


class TestIndeterminateResourcesStaySeparate:
    def test_an_unreadable_neighbour_is_not_reported_as_related(self) -> None:
        estate = exposure_estate()
        estate[1] = resource("sg-open", "security_group", attributes={})  # attribute absent
        finding = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], estate)["open-sg"]

        assert finding.status is FindingStatus.INDETERMINATE
        # The whole point of three-valued evaluation, carried into the
        # finding: "we could not read this" must never appear as "this is
        # confirmed related".
        assert finding.related_resources == ()
        assert finding.indeterminate_resources == ("sg-open",)


class TestGraphContext:
    def test_attached_only_when_the_rule_traversed_the_graph(self) -> None:
        estate = exposure_estate()
        traversing = rule("open-sg", ATTACHED_TO_OPEN_SG)
        single = rule("public-ip", {"field": "public_ip", "operator": "exists"})
        findings = scan([traversing, single], estate)
        assert findings["open-sg"].graph_context is not None
        assert findings["public-ip"].graph_context is None

    def test_context_describes_the_subject_neighbourhood(self) -> None:
        context = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate())[
            "open-sg"
        ].graph_context
        assert context is not None
        targets = {edge["target"] for edge in context["outgoing"]}
        assert targets == {"sg-open", "sg-closed"}

    def test_context_is_read_only(self) -> None:
        context = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate())[
            "open-sg"
        ].graph_context
        assert context is not None
        with pytest.raises(TypeError):
            context["outgoing"] = []  # type: ignore[index]


class TestDeterminism:
    def test_two_identical_scans_produce_identical_context(self) -> None:
        first = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate())["open-sg"]
        second = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], exposure_estate())["open-sg"]
        assert first.related_resources == second.related_resources
        assert dict(first.graph_context or {}) == dict(second.graph_context or {})

    def test_resource_input_order_does_not_change_the_context(self) -> None:
        estate = exposure_estate()
        forward = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], estate)["open-sg"]
        reversed_ = scan([rule("open-sg", ATTACHED_TO_OPEN_SG)], list(reversed(estate)))["open-sg"]
        assert forward.related_resources == reversed_.related_resources


class TestTraceUnit:
    """The recorder itself, independent of the use case."""

    def _obs(self, neighbor, satisfied, *, absence=False):
        return RelationshipObservation(
            relationship_type=RelationshipType.ATTACHED_TO,
            direction="outgoing",
            neighbor_id=ResourceId(neighbor),
            neighbor_type="security_group",
            satisfied=satisfied,
            from_absence_check=absence,
        )

    def test_matched_ids_are_sorted_and_deduplicated(self) -> None:
        trace = RelationshipTrace()
        for n in ("sg-z", "sg-a", "sg-z"):
            trace.record(self._obs(n, True))
        assert trace.matched_resource_ids == ("sg-a", "sg-z")

    def test_absence_observations_are_excluded_from_related(self) -> None:
        trace = RelationshipTrace()
        trace.record(self._obs("pe-1", True, absence=True))
        # Under `no_relationship`, a satisfying neighbour is evidence the
        # control was MET. Listing it beside a violation would name a
        # resource as implicated in a finding it in fact prevented.
        assert trace.matched_resource_ids == ()
        assert trace.traversed is True

    def test_indeterminate_ids_are_reported_separately(self) -> None:
        trace = RelationshipTrace()
        trace.record(self._obs("sg-1", None))
        trace.record(self._obs("sg-2", True))
        assert trace.matched_resource_ids == ("sg-2",)
        assert trace.indeterminate_resource_ids == ("sg-1",)

    def test_an_untouched_trace_reports_no_traversal(self) -> None:
        assert RelationshipTrace().traversed is False


class TestEvaluationIsUnchangedByTracing:
    """The trace must not alter what a rule decides."""

    def test_result_is_identical_with_and_without_a_trace(self) -> None:
        from domain.rules.conditions import evaluate_condition

        estate = exposure_estate()
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=estate)
        by_id = {r.resource_id: r for r in estate}
        subject = estate[0]

        untraced = evaluate_condition(
            ATTACHED_TO_OPEN_SG, subject, graph=graph, resources_by_id=by_id
        )
        traced = evaluate_condition(
            ATTACHED_TO_OPEN_SG,
            subject,
            graph=graph,
            resources_by_id=by_id,
            trace=RelationshipTrace(),
        )
        assert untraced is traced


class TestFindingInvariants:
    def test_related_resources_must_be_sorted(self) -> None:
        from domain.findings.models import Evidence
        from domain.shared.errors import InvalidFinding
        from domain.shared.identifiers import FindingId

        with pytest.raises(InvalidFinding, match="sorted"):
            Finding(
                id=FindingId("f-1"),
                tenant_id=TENANT,
                resource_id=ResourceId("i-web"),
                rule_id=RuleId("r-1"),
                framework="iso_27001",
                control_id="A.8.20",
                domain="network",
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                evidence=Evidence(data={}),
                detected_at=NOW,
                related_resources=("sg-z", "sg-a"),
            )
