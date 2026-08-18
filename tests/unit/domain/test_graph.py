import pytest

from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.shared.enums import RelationshipType
from domain.shared.errors import (
    GraphIntegrityViolation,
    TenantIsolationViolation,
)
from domain.shared.identifiers import ResourceId, TenantId

TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def node(resource_id: str, tenant_id: TenantId = TENANT_A, resource_type: str = "s3_bucket") -> GraphNode:
    return GraphNode(resource_id=ResourceId(resource_id), tenant_id=tenant_id, resource_type=resource_type)


class TestGraphNode:
    def test_valid_node(self) -> None:
        n = node("bucket-1")
        assert n.resource_id == ResourceId("bucket-1")
        assert n.tenant_id == TENANT_A

    def test_blank_resource_type_is_rejected(self) -> None:
        with pytest.raises(Exception):
            GraphNode(resource_id=ResourceId("bucket-1"), tenant_id=TENANT_A, resource_type="")


class TestGraphEdge:
    def test_valid_edge_defaults_to_not_blocked(self) -> None:
        edge = GraphEdge(
            source_id=ResourceId("sg-1"),
            target_id=ResourceId("bucket-1"),
            relationship_type=RelationshipType.PROTECTS,
        )
        assert edge.blocked is False

    def test_relationship_type_must_be_from_closed_vocabulary(self) -> None:
        with pytest.raises(Exception):
            GraphEdge(
                source_id=ResourceId("sg-1"),
                target_id=ResourceId("bucket-1"),
                relationship_type="invents_a_relation",  # type: ignore[arg-type]
            )


class TestResourceGraphNodes:
    def test_add_node(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("bucket-1"))
        assert graph.has_node(ResourceId("bucket-1"))
        assert graph.get_node(ResourceId("bucket-1")).resource_type == "s3_bucket"
        assert len(graph.nodes) == 1

    def test_duplicate_node_is_rejected(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("bucket-1"))
        with pytest.raises(GraphIntegrityViolation):
            graph.add_node(node("bucket-1"))

    def test_tenant_isolation_rejects_foreign_tenant_node(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        with pytest.raises(TenantIsolationViolation):
            graph.add_node(node("bucket-1", tenant_id=TENANT_B))

    def test_rejected_foreign_node_is_not_partially_added(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        with pytest.raises(TenantIsolationViolation):
            graph.add_node(node("bucket-1", tenant_id=TENANT_B))
        assert graph.nodes == ()


class TestResourceGraphEdges:
    def test_add_edge_between_existing_nodes(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("sg-1"))
        graph.add_node(node("bucket-1"))
        edge = GraphEdge(
            source_id=ResourceId("sg-1"),
            target_id=ResourceId("bucket-1"),
            relationship_type=RelationshipType.PROTECTS,
        )
        graph.add_edge(edge)
        assert graph.edges == (edge,)

    def test_add_edge_rejects_missing_source_node(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("bucket-1"))
        edge = GraphEdge(
            source_id=ResourceId("sg-missing"),
            target_id=ResourceId("bucket-1"),
            relationship_type=RelationshipType.PROTECTS,
        )
        with pytest.raises(GraphIntegrityViolation):
            graph.add_edge(edge)

    def test_add_edge_rejects_missing_target_node(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("sg-1"))
        edge = GraphEdge(
            source_id=ResourceId("sg-1"),
            target_id=ResourceId("bucket-missing"),
            relationship_type=RelationshipType.PROTECTS,
        )
        with pytest.raises(GraphIntegrityViolation):
            graph.add_edge(edge)

    def test_valid_relationship_types_are_all_accepted(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("a"))
        graph.add_node(node("b"))
        for relationship_type in RelationshipType:
            edge = GraphEdge(
                source_id=ResourceId("a"),
                target_id=ResourceId("b"),
                relationship_type=relationship_type,
            )
            graph.add_edge(edge)
        assert len(graph.edges) == len(RelationshipType)

    def test_blocked_edge_is_preserved(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("a"))
        graph.add_node(node("b"))
        edge = GraphEdge(
            source_id=ResourceId("a"),
            target_id=ResourceId("b"),
            relationship_type=RelationshipType.CONNECTS_TO,
            blocked=True,
        )
        graph.add_edge(edge)
        assert graph.edges[0].blocked is True


class TestResourceGraphNeighbors:
    def _graph_with_edge(self, relationship_type=RelationshipType.ATTACHED_TO):
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("ec2-1", resource_type="ec2_instance"))
        graph.add_node(node("sg-1", resource_type="security_group"))
        graph.add_edge(
            GraphEdge(source_id=ResourceId("ec2-1"), target_id=ResourceId("sg-1"), relationship_type=relationship_type)
        )
        return graph

    def test_outgoing_neighbors_by_relationship_type(self) -> None:
        graph = self._graph_with_edge()
        neighbors = graph.neighbors(ResourceId("ec2-1"), RelationshipType.ATTACHED_TO, direction="outgoing")
        assert [n.resource_id for n in neighbors] == [ResourceId("sg-1")]

    def test_incoming_neighbors_by_relationship_type(self) -> None:
        graph = self._graph_with_edge()
        neighbors = graph.neighbors(ResourceId("sg-1"), RelationshipType.ATTACHED_TO, direction="incoming")
        assert [n.resource_id for n in neighbors] == [ResourceId("ec2-1")]

    def test_wrong_direction_returns_no_neighbors(self) -> None:
        graph = self._graph_with_edge()
        neighbors = graph.neighbors(ResourceId("sg-1"), RelationshipType.ATTACHED_TO, direction="outgoing")
        assert neighbors == ()

    def test_wrong_relationship_type_returns_no_neighbors(self) -> None:
        graph = self._graph_with_edge(relationship_type=RelationshipType.ATTACHED_TO)
        neighbors = graph.neighbors(ResourceId("ec2-1"), RelationshipType.ALLOWS, direction="outgoing")
        assert neighbors == ()

    def test_node_with_no_edges_has_no_neighbors(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("lonely"))
        neighbors = graph.neighbors(ResourceId("lonely"), RelationshipType.ATTACHED_TO, direction="outgoing")
        assert neighbors == ()

    def test_unknown_source_node_has_no_neighbors_not_an_error(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        neighbors = graph.neighbors(ResourceId("does-not-exist"), RelationshipType.ATTACHED_TO, direction="outgoing")
        assert neighbors == ()

    def test_multiple_neighbors_via_same_relationship(self) -> None:
        graph = ResourceGraph(tenant_id=TENANT_A)
        graph.add_node(node("sg-1"))
        graph.add_node(node("sg-2"))
        graph.add_node(node("sg-3"))
        graph.add_edge(GraphEdge(source_id=ResourceId("sg-1"), target_id=ResourceId("sg-2"), relationship_type=RelationshipType.ALLOWS))
        graph.add_edge(GraphEdge(source_id=ResourceId("sg-1"), target_id=ResourceId("sg-3"), relationship_type=RelationshipType.ALLOWS))
        neighbors = graph.neighbors(ResourceId("sg-1"), RelationshipType.ALLOWS, direction="outgoing")
        assert {n.resource_id for n in neighbors} == {ResourceId("sg-2"), ResourceId("sg-3")}
