from datetime import datetime, timezone

import pytest

from application.graph.build_resource_graph import BuildResourceGraph
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import GraphIntegrityViolation, TenantIsolationViolation
from domain.shared.identifiers import ResourceId, TenantId

COLLECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def make_resource(resource_id: str, tenant_id=TENANT_A, relationships=(), resource_type="s3_bucket"):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region="us-east-1",
        attributes={},
        tags={},
        relationships=relationships,
        collected_at=COLLECTED_AT,
    )


class TestBuildResourceGraph:
    def test_builds_nodes_for_every_resource(self) -> None:
        resources = [make_resource("bucket-1"), make_resource("sg-1")]
        graph = BuildResourceGraph().build(tenant_id=TENANT_A, resources=resources)
        assert graph.has_node(ResourceId("bucket-1"))
        assert graph.has_node(ResourceId("sg-1"))
        assert len(graph.nodes) == 2

    def test_builds_edges_from_relationships(self) -> None:
        bucket = make_resource("bucket-1")
        sg = make_resource(
            "sg-1",
            resource_type="security_group",
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("bucket-1"),
                    relationship_type=RelationshipType.PROTECTS,
                ),
            ),
        )
        graph = BuildResourceGraph().build(tenant_id=TENANT_A, resources=[bucket, sg])
        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.source_id == ResourceId("sg-1")
        assert edge.target_id == ResourceId("bucket-1")
        assert edge.relationship_type is RelationshipType.PROTECTS
        assert edge.blocked is False

    def test_relationship_order_does_not_matter_nodes_added_before_edges(self) -> None:
        # sg-1 references bucket-1, but bucket-1 appears LATER in the input list.
        sg = make_resource(
            "sg-1",
            resource_type="security_group",
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("bucket-1"),
                    relationship_type=RelationshipType.PROTECTS,
                ),
            ),
        )
        bucket = make_resource("bucket-1")
        graph = BuildResourceGraph().build(tenant_id=TENANT_A, resources=[sg, bucket])
        assert len(graph.edges) == 1

    def test_graph_still_refuses_a_dangling_edge_at_the_aggregate(self) -> None:
        """The referential-integrity invariant, unchanged.

        This replaces an earlier test that asserted ``BuildResourceGraph``
        *raises* on a relationship to an uncollected resource. That
        builder behaviour was changed deliberately — it was a blocker:
        `IamRoleCollector` legitimately points at the internet, an AWS
        service principal and foreign accounts, none of which are
        collectible resources, so the raise aborted every scan involving
        an IAM role with a trust policy.

        The invariant itself is NOT weakened. ``ResourceGraph.add_edge``
        still refuses a dangling edge, which is asserted here directly
        against the aggregate that owns the rule. What changed is that
        the builder now materializes external targets as nodes (below)
        instead of propagating the failure.
        """

        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(
            GraphNode(
                resource_id=ResourceId("sg-1"),
                tenant_id=TENANT_A,
                resource_type="security_group",
            )
        )
        with pytest.raises(GraphIntegrityViolation):
            graph.add_edge(
                GraphEdge(
                    source_id=ResourceId("sg-1"),
                    target_id=ResourceId("does-not-exist"),
                    relationship_type=RelationshipType.PROTECTS,
                )
            )

    def test_builder_materializes_an_uncollected_target_as_an_external_node(self) -> None:
        sg = make_resource(
            "sg-1",
            resource_type="security_group",
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("does-not-exist"),
                    relationship_type=RelationshipType.PROTECTS,
                ),
            ),
        )
        graph = BuildResourceGraph().build(tenant_id=TENANT_A, resources=[sg])

        # The edge survives — for an exposure relationship it IS the
        # finding — and the target is marked external so a rule can tell
        # "points outside the scan" from "points at a collected resource".
        assert len(graph.edges) == 1
        assert graph.get_node(ResourceId("does-not-exist")).is_external is True

    def test_foreign_tenant_resource_raises_tenant_isolation_violation(self) -> None:
        resources = [make_resource("bucket-1", tenant_id=TENANT_B)]
        with pytest.raises(TenantIsolationViolation):
            BuildResourceGraph().build(tenant_id=TENANT_A, resources=resources)

    def test_empty_resource_collection_builds_an_empty_graph(self) -> None:
        graph = BuildResourceGraph().build(tenant_id=TENANT_A, resources=[])
        assert graph.nodes == ()
        assert graph.edges == ()

    def test_build_is_deterministic(self) -> None:
        resources = [make_resource("bucket-1"), make_resource("sg-1")]
        first = BuildResourceGraph().build(tenant_id=TENANT_A, resources=resources)
        second = BuildResourceGraph().build(tenant_id=TENANT_A, resources=resources)
        assert {n.resource_id for n in first.nodes} == {n.resource_id for n in second.nodes}
