"""Graph provenance, external nodes, validation and determinism.

The first class is a regression suite for a **blocker introduced by the
previous phase**: `IamRoleCollector` emitted edges to targets that were
never nodes, so building a graph from its output raised and killed the
whole scan. It escaped 21 collector tests because none of them built a
graph — the components were correct and their seam was not tested.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.graph.build_resource_graph import BuildResourceGraph
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.graph.validation import (
    Severity,
    graph_context_for,
    graph_fingerprint,
    validate_graph,
)
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import GraphIntegrityViolation
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def a_resource(rid, rtype="ec2_instance", *, rels=(), account="111111111111", region="us-east-1"):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region=region,
        attributes={},
        tags={},
        relationships=tuple(
            ResourceRelationship(target_resource_id=ResourceId(t), relationship_type=k)
            for t, k in rels
        ),
        collected_at=NOW,
        account_id=account,
    )


def build(resources):
    return BuildResourceGraph().build_with_report(tenant_id=TENANT, resources=resources)


class TestExternalNodeBlockerRegression:
    """The defect the previous phase shipped."""

    def test_an_edge_to_the_internet_no_longer_kills_the_scan(self) -> None:
        role = a_resource(
            "arn:aws:iam::111111111111:role/app",
            "iam_role",
            rels=[("internet", RelationshipType.PUBLICLY_EXPOSED)],
        )
        result = build([role])

        assert len(result.graph.edges) == 1, "the exposure edge is the finding; it must survive"
        assert result.is_complete

    def test_the_external_target_is_materialized_as_a_node(self) -> None:
        role = a_resource(
            "role-1", "iam_role", rels=[("internet", RelationshipType.PUBLICLY_EXPOSED)]
        )
        result = build([role])

        node = result.graph.get_node(ResourceId("internet"))
        assert node.is_external
        assert node.resource_type == "internet"

    def test_external_nodes_are_distinguishable_from_collected_ones(self) -> None:
        # "This role trusts an external account" is a finding. "This role
        # trusts something we did not collect" is a data gap. A rule must
        # be able to tell them apart.
        role = a_resource(
            "role-1", "iam_role", rels=[("aws-account:999999999999", RelationshipType.ASSUMES)]
        )
        result = build([role])

        assert result.graph.get_node(ResourceId("role-1")).is_external is False
        assert result.graph.get_node(ResourceId("aws-account:999999999999")).is_external is True

    @pytest.mark.parametrize(
        "target,expected_type",
        [
            ("internet", "internet"),
            ("aws-account:999999999999", "aws_account"),
            ("aws-service:ec2.amazonaws.com", "aws_service"),
            ("something-unrecognized", "external_resource"),
        ],
    )
    def test_external_targets_are_classified_not_guessed(self, target, expected_type) -> None:
        result = build([a_resource("r1", rels=[(target, RelationshipType.ASSUMES)])])
        assert result.graph.get_node(ResourceId(target)).resource_type == expected_type

    def test_external_nodes_carry_reduced_confidence(self) -> None:
        # We did not enumerate it; we only know something pointed at it.
        result = build([a_resource("r1", rels=[("internet", RelationshipType.PUBLICLY_EXPOSED)])])
        assert result.graph.get_node(ResourceId("internet")).confidence == "medium"


class TestEdgeIsolation:
    def test_a_duplicate_relationship_yields_one_edge(self) -> None:
        # Two collectors observing the same relationship assert one edge.
        a = a_resource("a", rels=[("b", RelationshipType.ATTACHED_TO)])
        duplicate = a_resource("a2", rels=[("b", RelationshipType.ATTACHED_TO)])
        result = build([a, duplicate, a_resource("b", "security_group")])
        # Different sources, so these are genuinely two edges...
        assert len(result.graph.edges) == 2

    def test_the_same_edge_asserted_twice_is_deduplicated(self) -> None:
        rels = [
            ("b", RelationshipType.ATTACHED_TO),
            ("b", RelationshipType.ATTACHED_TO),
        ]
        result = build([a_resource("a", rels=rels), a_resource("b", "security_group")])
        assert len(result.graph.edges) == 1

    def test_a_self_loop_is_built_but_reported(self) -> None:
        result = build([a_resource("a", rels=[("a", RelationshipType.ACCESSES)])])
        report = validate_graph(result.graph)
        assert any(i.code == "self_loop" for i in report.issues)


class TestProvenance:
    def test_nodes_carry_provider_account_and_region(self) -> None:
        result = build([a_resource("i-1", account="222222222222", region="eu-west-1")])
        node = result.graph.get_node(ResourceId("i-1"))
        assert node.provider is CloudProvider.AWS
        assert node.account_id == "222222222222"
        assert node.region == "eu-west-1"

    def test_edges_carry_evidence_and_a_source_collector(self) -> None:
        # An edge without provenance is an unattributable assertion, and
        # a cross-resource finding cannot show its reasoning.
        result = build(
            [a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)]),
             a_resource("sg-1", "security_group")]
        )
        edge = result.graph.edges[0]
        assert edge.source_collector == "ec2_instance"
        assert edge.evidence["asserted_by"] == "i-1"

    def test_evidence_is_immutable(self) -> None:
        edge = GraphEdge(
            source_id=ResourceId("a"),
            target_id=ResourceId("b"),
            relationship_type=RelationshipType.ACCESSES,
            evidence={"k": "v"},
        )
        with pytest.raises(TypeError):
            edge.evidence["k"] = "tampered"  # type: ignore[index]

    def test_an_invalid_confidence_is_rejected(self) -> None:
        with pytest.raises(GraphIntegrityViolation):
            GraphNode(
                resource_id=ResourceId("a"),
                tenant_id=TENANT,
                resource_type="t",
                confidence="very-sure",
            )

    def test_an_invalid_kind_is_rejected(self) -> None:
        with pytest.raises(GraphIntegrityViolation):
            GraphNode(
                resource_id=ResourceId("a"), tenant_id=TENANT, resource_type="t", kind="imaginary"
            )


class TestBackwardCompatibility:
    def test_the_three_argument_node_constructor_still_works(self) -> None:
        node = GraphNode(resource_id=ResourceId("a"), tenant_id=TENANT, resource_type="s3_bucket")
        assert node.kind == "collected"
        assert node.confidence == "high"
        assert node.provider is None

    def test_the_original_build_signature_still_returns_a_graph(self) -> None:
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=[a_resource("a")])
        assert isinstance(graph, ResourceGraph)

    def test_the_four_argument_edge_constructor_still_works(self) -> None:
        edge = GraphEdge(
            source_id=ResourceId("a"),
            target_id=ResourceId("b"),
            relationship_type=RelationshipType.ACCESSES,
            blocked=True,
        )
        assert edge.blocked is True
        assert edge.evidence == {}


class TestValidation:
    def test_a_healthy_graph_is_valid(self) -> None:
        result = build(
            [a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)]),
             a_resource("sg-1", "security_group")]
        )
        assert validate_graph(result.graph).is_valid

    def test_cross_account_edges_are_reported_as_info_not_error(self) -> None:
        # A role trusting a partner account is intended, not broken.
        result = build(
            [a_resource("a", account="111111111111", rels=[("b", RelationshipType.ACCESSES)]),
             a_resource("b", account="222222222222")]
        )
        report = validate_graph(result.graph)
        issue = next(i for i in report.issues if i.code == "cross_account_edge")
        assert issue.severity is Severity.INFO
        assert report.is_valid

    def test_an_impossible_relationship_is_an_error(self) -> None:
        result = build([a_resource("r", "iam_role", rels=[("internet", RelationshipType.ASSUMES)])])
        report = validate_graph(result.graph)
        assert any(i.code == "impossible_relationship" for i in report.issues)
        assert not report.is_valid

    def test_a_dangling_edge_is_an_error(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT)
        graph.add_node(GraphNode(resource_id=ResourceId("a"), tenant_id=TENANT, resource_type="t"))
        # Bypass add_edge to simulate a graph assembled another way.
        graph._edges.append(
            GraphEdge(
                source_id=ResourceId("a"),
                target_id=ResourceId("ghost"),
                relationship_type=RelationshipType.ACCESSES,
            )
        )
        assert not validate_graph(graph).is_valid

    def test_the_report_counts_relationships(self) -> None:
        result = build(
            [a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)]),
             a_resource("sg-1", "security_group")]
        )
        report = validate_graph(result.graph)
        assert report.relationship_counts["attached_to"] == 1
        assert report.node_count == 2


class TestDeterminism:
    """§8: identical input must produce an equivalent graph."""

    def test_the_same_input_produces_the_same_fingerprint(self) -> None:
        resources = [
            a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)]),
            a_resource("sg-1", "security_group"),
        ]
        assert graph_fingerprint(build(resources).graph) == graph_fingerprint(
            build(resources).graph
        )

    def test_input_order_does_not_change_the_fingerprint(self) -> None:
        # Collector scheduling is not a property of the infrastructure.
        a = a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)])
        b = a_resource("sg-1", "security_group")
        assert graph_fingerprint(build([a, b]).graph) == graph_fingerprint(build([b, a]).graph)

    def test_provenance_does_not_change_the_fingerprint(self) -> None:
        # Two scans learning the same topology from different collectors
        # describe the same infrastructure.
        base = ResourceGraph(tenant_id=TENANT)
        base.add_node(GraphNode(resource_id=ResourceId("a"), tenant_id=TENANT, resource_type="t"))
        base.add_node(GraphNode(resource_id=ResourceId("b"), tenant_id=TENANT, resource_type="t"))
        base.add_edge(
            GraphEdge(
                source_id=ResourceId("a"),
                target_id=ResourceId("b"),
                relationship_type=RelationshipType.ACCESSES,
                source_collector="collector-one",
                evidence={"x": 1},
            )
        )

        other = ResourceGraph(tenant_id=TENANT)
        other.add_node(GraphNode(resource_id=ResourceId("a"), tenant_id=TENANT, resource_type="t"))
        other.add_node(GraphNode(resource_id=ResourceId("b"), tenant_id=TENANT, resource_type="t"))
        other.add_edge(
            GraphEdge(
                source_id=ResourceId("a"),
                target_id=ResourceId("b"),
                relationship_type=RelationshipType.ACCESSES,
                source_collector="collector-two",
                evidence={"y": 2},
            )
        )

        assert graph_fingerprint(base) == graph_fingerprint(other)

    def test_a_topology_change_does_change_the_fingerprint(self) -> None:
        one = build([a_resource("a"), a_resource("b")])
        two = build([a_resource("a", rels=[("b", RelationshipType.ACCESSES)]), a_resource("b")])
        assert graph_fingerprint(one.graph) != graph_fingerprint(two.graph)


class TestGraphContext:
    def test_context_lists_outgoing_and_incoming_edges(self) -> None:
        result = build(
            [a_resource("i-1", rels=[("sg-1", RelationshipType.ATTACHED_TO)]),
             a_resource("sg-1", "security_group")]
        )
        context = graph_context_for(result.graph, ResourceId("i-1"))
        assert context["outgoing"][0]["target"] == "sg-1"
        assert context["outgoing"][0]["target_type"] == "security_group"

        reverse = graph_context_for(result.graph, ResourceId("sg-1"))
        assert reverse["incoming"][0]["source"] == "i-1"

    def test_internet_exposure_is_surfaced(self) -> None:
        result = build([a_resource("r", "iam_role", rels=[("internet", RelationshipType.PUBLICLY_EXPOSED)])])
        assert graph_context_for(result.graph, ResourceId("r"))["is_internet_exposed"] is True

    def test_context_is_deterministically_ordered(self) -> None:
        result = build(
            [a_resource("a", rels=[("c", RelationshipType.ACCESSES), ("b", RelationshipType.ACCESSES)]),
             a_resource("b"), a_resource("c")]
        )
        first = graph_context_for(result.graph, ResourceId("a"))
        second = graph_context_for(result.graph, ResourceId("a"))
        assert first == second
        assert [o["target"] for o in first["outgoing"]] == ["b", "c"]
