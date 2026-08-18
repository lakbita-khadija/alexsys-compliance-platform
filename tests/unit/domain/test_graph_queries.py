"""Tests for ``domain.graph.queries`` (expansion §1.6, §15).

Two themes run through this file.

**Index/scan agreement.** The audit's regression table named exactly one
risk for this phase: "silent divergence between index and edge list". A
stale index does not raise — it makes a cross-resource rule quietly stop
firing, which is indistinguishable from the rule finding nothing. So the
index-backed queries are asserted against an independent linear scan of
the authoritative collections, not against hand-written expectations.

**Determinism.** Every ordering assertion here exists because a finding
whose evidence lists resources in a different order on every scan is a
finding nobody can diff.
"""

from __future__ import annotations

import pytest

from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.graph.queries import (
    INTERNET,
    edges_of,
    find_paths,
    find_resources,
    find_resources_exposed_to_internet,
    find_resources_using_identity,
    find_resources_without_relationship,
    graph_statistics,
    has_relationship,
    internet_node_ids,
    iter_edges,
    related_nodes,
)
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import GraphIntegrityViolation
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")

RT = RelationshipType


def node(
    resource_id: str,
    resource_type: str = "ec2_instance",
    *,
    kind: str = "collected",
    provider: CloudProvider | None = CloudProvider.AWS,
) -> GraphNode:
    return GraphNode(
        resource_id=ResourceId(resource_id),
        tenant_id=TENANT,
        resource_type=resource_type,
        provider=provider,
        kind=kind,
    )


def edge(
    source: str,
    target: str,
    relationship_type: RelationshipType,
    *,
    blocked: bool = False,
) -> GraphEdge:
    return GraphEdge(
        source_id=ResourceId(source),
        target_id=ResourceId(target),
        relationship_type=relationship_type,
        blocked=blocked,
    )


def build(nodes: list[GraphNode], edges: list[GraphEdge]) -> ResourceGraph:
    graph = ResourceGraph(tenant_id=TENANT)
    for n in nodes:
        graph.add_node(n)
    for e in edges:
        graph.add_edge(e)
    return graph


@pytest.fixture
def exposure_graph() -> ResourceGraph:
    """A small but realistic exposure chain.

        internet ◀── sg-open ◀── i-web ──▶ role/app ──▶ bucket-data
                                   │
                                   └──▶ sg-closed

    Shaped after the scenario `resource-graph.md` §2 describes: no single
    resource here is a finding on its own.
    """

    return build(
        [
            node("internet", "internet", kind="external", provider=None),
            node("sg-open", "security_group"),
            node("sg-closed", "security_group"),
            node("i-web", "ec2_instance"),
            node("role/app", "iam_role"),
            node("bucket-data", "s3_bucket"),
        ],
        [
            edge("sg-open", "internet", RT.PUBLICLY_EXPOSED),
            edge("i-web", "sg-open", RT.ATTACHED_TO),
            edge("i-web", "sg-closed", RT.ATTACHED_TO),
            edge("i-web", "role/app", RT.ASSUMES),
            edge("role/app", "bucket-data", RT.ACCESSES),
        ],
    )


class TestIndexScanAgreement:
    """The audit's named regression risk, asserted directly.

    Each of these compares an index-backed query against an independent
    linear scan of ``graph.nodes`` / ``graph.edges``, which remain the
    authoritative collections. If ``add_node``/``add_edge`` ever stop
    maintaining an index, these fail rather than a rule silently going
    quiet.
    """

    def test_outgoing_index_matches_a_linear_scan_for_every_node(
        self, exposure_graph: ResourceGraph
    ) -> None:
        for n in exposure_graph.nodes:
            scanned = sorted(
                (e for e in exposure_graph.edges if e.source_id == n.resource_id),
                key=lambda e: (str(e.source_id), str(e.target_id), e.relationship_type.value),
            )
            assert list(edges_of(exposure_graph, n.resource_id)) == scanned

    def test_incoming_index_matches_a_linear_scan_for_every_node(
        self, exposure_graph: ResourceGraph
    ) -> None:
        for n in exposure_graph.nodes:
            scanned = sorted(
                (e for e in exposure_graph.edges if e.target_id == n.resource_id),
                key=lambda e: (str(e.source_id), str(e.target_id), e.relationship_type.value),
            )
            assert list(edges_of(exposure_graph, n.resource_id, direction="incoming")) == scanned

    def test_type_index_matches_a_linear_scan_for_every_type(
        self, exposure_graph: ResourceGraph
    ) -> None:
        for resource_type in {n.resource_type for n in exposure_graph.nodes}:
            scanned = {
                n.resource_id
                for n in exposure_graph.nodes
                if n.resource_type == resource_type
            }
            assert {
                n.resource_id for n in find_resources(exposure_graph, resource_type)
            } == scanned

    def test_every_edge_appears_in_exactly_one_outgoing_bucket(
        self, exposure_graph: ResourceGraph
    ) -> None:
        indexed = [e for n in exposure_graph.nodes for e in edges_of(exposure_graph, n.resource_id)]
        assert len(indexed) == len(exposure_graph.edges)
        assert set(map(id, indexed)) == set(map(id, exposure_graph.edges))


class TestEdgesOf:
    def test_outgoing_is_the_default_direction(self, exposure_graph: ResourceGraph) -> None:
        assert {str(e.target_id) for e in edges_of(exposure_graph, ResourceId("i-web"))} == {
            "sg-open",
            "sg-closed",
            "role/app",
        }

    def test_incoming_direction(self, exposure_graph: ResourceGraph) -> None:
        assert [str(e.source_id) for e in edges_of(
            exposure_graph, ResourceId("internet"), direction="incoming"
        )] == ["sg-open"]

    def test_relationship_type_filter(self, exposure_graph: ResourceGraph) -> None:
        edges = edges_of(exposure_graph, ResourceId("i-web"), relationship_type=RT.ASSUMES)
        assert [str(e.target_id) for e in edges] == ["role/app"]

    def test_unknown_resource_returns_empty_rather_than_raising(
        self, exposure_graph: ResourceGraph
    ) -> None:
        # "No relationship exists" is a determinate fact about the graph,
        # not a failure — the same contract ResourceGraph.neighbors has.
        assert edges_of(exposure_graph, ResourceId("nope")) == ()

    def test_result_is_sorted_regardless_of_insertion_order(self) -> None:
        nodes = [node("a"), node("b"), node("c")]
        forward = build(nodes[:], [edge("a", "b", RT.ACCESSES), edge("a", "c", RT.ACCESSES)])
        reverse = build(nodes[:], [edge("a", "c", RT.ACCESSES), edge("a", "b", RT.ACCESSES)])

        assert [str(e.target_id) for e in edges_of(forward, ResourceId("a"))] == ["b", "c"]
        assert [str(e.target_id) for e in edges_of(reverse, ResourceId("a"))] == ["b", "c"]


class TestRelatedNodes:
    def test_returns_nodes_one_hop_away(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in related_nodes(
            exposure_graph, ResourceId("i-web")
        )] == ["role/app", "sg-closed", "sg-open"]

    def test_target_type_filter(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in related_nodes(
            exposure_graph, ResourceId("i-web"), target_type="security_group"
        )] == ["sg-closed", "sg-open"]

    def test_incoming_direction_returns_sources(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in related_nodes(
            exposure_graph, ResourceId("sg-open"), direction="incoming"
        )] == ["i-web"]

    def test_unknown_resource_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert related_nodes(exposure_graph, ResourceId("nope")) == ()

    def test_relationship_and_target_type_filters_compose(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert related_nodes(
            exposure_graph,
            ResourceId("i-web"),
            relationship_type=RT.ASSUMES,
            target_type="security_group",
        ) == ()


class TestFindResources:
    def test_returns_every_node_of_a_type(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in find_resources(
            exposure_graph, "security_group"
        )] == ["sg-closed", "sg-open"]

    def test_unknown_type_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert find_resources(exposure_graph, "rds_instance") == ()

    def test_external_nodes_are_findable_by_their_type(
        self, exposure_graph: ResourceGraph
    ) -> None:
        internet = find_resources(exposure_graph, "internet")
        assert len(internet) == 1
        assert internet[0].is_external is True


class TestHasRelationship:
    def test_true_for_an_existing_edge(self, exposure_graph: ResourceGraph) -> None:
        assert has_relationship(
            exposure_graph,
            source=ResourceId("i-web"),
            relationship_type=RT.ATTACHED_TO,
            target=ResourceId("sg-open"),
        )

    def test_false_when_the_relationship_type_differs(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert not has_relationship(
            exposure_graph,
            source=ResourceId("i-web"),
            relationship_type=RT.ASSUMES,
            target=ResourceId("sg-open"),
        )

    def test_false_for_the_reversed_direction(self, exposure_graph: ResourceGraph) -> None:
        # Edges are directed. "sg-open is attached to i-web" is a
        # different assertion from "i-web is attached to sg-open", and
        # conflating them would let a rule invert causality.
        assert not has_relationship(
            exposure_graph,
            source=ResourceId("sg-open"),
            relationship_type=RT.ATTACHED_TO,
            target=ResourceId("i-web"),
        )


class TestFindPaths:
    def test_finds_a_multi_hop_path(self, exposure_graph: ResourceGraph) -> None:
        paths = find_paths(
            exposure_graph, source=ResourceId("i-web"), target=ResourceId("bucket-data")
        )
        assert len(paths) == 1
        assert [str(e.target_id) for e in paths[0]] == ["role/app", "bucket-data"]

    def test_returns_empty_when_no_path_exists(self, exposure_graph: ResourceGraph) -> None:
        assert find_paths(
            exposure_graph, source=ResourceId("bucket-data"), target=ResourceId("i-web")
        ) == ()

    def test_max_depth_bounds_the_search(self, exposure_graph: ResourceGraph) -> None:
        # The path is two hops; a one-hop budget must not find it.
        assert find_paths(
            exposure_graph,
            source=ResourceId("i-web"),
            target=ResourceId("bucket-data"),
            max_depth=1,
        ) == ()

    def test_max_depth_below_one_is_rejected(self, exposure_graph: ResourceGraph) -> None:
        with pytest.raises(ValueError):
            find_paths(
                exposure_graph,
                source=ResourceId("i-web"),
                target=ResourceId("bucket-data"),
                max_depth=0,
            )

    def test_cycles_terminate(self) -> None:
        graph = build(
            [node("a"), node("b"), node("c")],
            [
                edge("a", "b", RT.ACCESSES),
                edge("b", "c", RT.ACCESSES),
                edge("c", "a", RT.ACCESSES),
            ],
        )
        paths = find_paths(graph, source=ResourceId("a"), target=ResourceId("c"), max_depth=10)
        assert len(paths) == 1
        assert [str(e.target_id) for e in paths[0]] == ["b", "c"]

    def test_blocked_edges_are_excluded_by_default(self) -> None:
        graph = build(
            [node("a"), node("b")],
            [edge("a", "b", RT.ACCESSES, blocked=True)],
        )
        # An edge marked blocked is a relationship that exists
        # structurally but is prevented in practice. Reporting it as a
        # walkable path is a false positive.
        assert find_paths(graph, source=ResourceId("a"), target=ResourceId("b")) == ()

    def test_blocked_edges_can_be_included_explicitly(self) -> None:
        graph = build(
            [node("a"), node("b")],
            [edge("a", "b", RT.ACCESSES, blocked=True)],
        )
        assert len(
            find_paths(
                graph, source=ResourceId("a"), target=ResourceId("b"), include_blocked=True
            )
        ) == 1

    def test_shorter_paths_are_reported_first(self) -> None:
        graph = build(
            [node("a"), node("b"), node("z")],
            [
                edge("a", "b", RT.ACCESSES),
                edge("b", "z", RT.ACCESSES),
                edge("a", "z", RT.ACCESSES),
            ],
        )
        paths = find_paths(graph, source=ResourceId("a"), target=ResourceId("z"))
        assert [len(p) for p in paths] == [1, 2]

    def test_ordering_is_independent_of_edge_insertion_order(self) -> None:
        nodes = [node("a"), node("b"), node("c"), node("z")]
        first = build(
            nodes[:],
            [
                edge("a", "b", RT.ACCESSES),
                edge("a", "c", RT.ACCESSES),
                edge("b", "z", RT.ACCESSES),
                edge("c", "z", RT.ACCESSES),
            ],
        )
        second = build(
            nodes[:],
            [
                edge("c", "z", RT.ACCESSES),
                edge("a", "c", RT.ACCESSES),
                edge("b", "z", RT.ACCESSES),
                edge("a", "b", RT.ACCESSES),
            ],
        )
        as_ids = lambda paths: [[str(e.target_id) for e in p] for p in paths]  # noqa: E731
        assert as_ids(
            find_paths(first, source=ResourceId("a"), target=ResourceId("z"))
        ) == as_ids(find_paths(second, source=ResourceId("a"), target=ResourceId("z")))

    def test_unknown_source_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert find_paths(
            exposure_graph, source=ResourceId("nope"), target=ResourceId("bucket-data")
        ) == ()


class TestInternetExposure:
    def test_finds_the_directly_exposed_resource(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in find_resources_exposed_to_internet(
            exposure_graph
        )] == ["sg-open"]

    def test_transitively_reachable_resources_are_not_reported_as_exposed(
        self, exposure_graph: ResourceGraph
    ) -> None:
        # i-web reaches the internet through sg-open, but it has no
        # direct exposure edge. Conflating the two would let a rule claim
        # direct exposure for a resource three hops away — that is what
        # find_paths is for.
        exposed = {str(n.resource_id) for n in find_resources_exposed_to_internet(exposure_graph)}
        assert "i-web" not in exposed

    def test_blocked_exposure_is_not_exposure(self) -> None:
        graph = build(
            [node("internet", "internet", kind="external", provider=None), node("sg-1")],
            [edge("sg-1", "internet", RT.PUBLICLY_EXPOSED, blocked=True)],
        )
        assert find_resources_exposed_to_internet(graph) == ()

    def test_graph_without_an_internet_node_reports_nothing(self) -> None:
        graph = build([node("a"), node("b")], [edge("a", "b", RT.ACCESSES)])
        assert find_resources_exposed_to_internet(graph) == ()
        assert internet_node_ids(graph) == ()

    def test_internet_node_ids_covers_both_conventions(self) -> None:
        # The conventional id collectors emit, and the type the builder
        # classifies. A query trusting only one would miss exposure.
        by_id = build([node("internet", "external_resource", kind="external", provider=None)], [])
        by_type = build([node("public-net", "internet", kind="external", provider=None)], [])
        assert internet_node_ids(by_id) == (INTERNET,)
        assert internet_node_ids(by_type) == (ResourceId("public-net"),)


class TestIdentityUsage:
    def test_finds_resources_that_assume_a_role(self, exposure_graph: ResourceGraph) -> None:
        assert [str(n.resource_id) for n in find_resources_using_identity(
            exposure_graph, ResourceId("role/app")
        )] == ["i-web"]

    def test_accesses_counts_as_identity_use(self) -> None:
        graph = build(
            [node("vm-1", "azure_vm"), node("mi-1", "managed_identity")],
            [edge("vm-1", "mi-1", RT.ACCESSES)],
        )
        assert [str(n.resource_id) for n in find_resources_using_identity(
            graph, ResourceId("mi-1")
        )] == ["vm-1"]

    def test_unused_identity_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert find_resources_using_identity(exposure_graph, ResourceId("sg-open")) == ()

    def test_unknown_resource_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert find_resources_using_identity(exposure_graph, ResourceId("nope")) == ()

    def test_a_data_resource_returns_its_readers_which_is_the_caller_hazard(
        self, exposure_graph: ResourceGraph
    ) -> None:
        """Pins the documented caller contract, deliberately.

        `role/app ACCESSES bucket-data`, so asking this function about
        the *bucket* returns the role. That is a true statement about
        the graph and a misleading answer to "who uses this identity" —
        because ACCESSES serves double duty: a VM using a managed
        identity and a role reading a bucket are the same edge type.

        Not guarded by default: hardcoding a list of identity resource
        types would invent a vocabulary ahead of the Entra ID collectors
        that would produce it. The next test shows the opt-in guard.
        """

        assert [str(n.resource_id) for n in find_resources_using_identity(
            exposure_graph, ResourceId("bucket-data")
        )] == ["role/app"]

    def test_identity_types_guard_rejects_a_non_identity_target(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert find_resources_using_identity(
            exposure_graph, ResourceId("bucket-data"), identity_types=["iam_role", "iam_user"]
        ) == ()

    def test_identity_types_guard_still_answers_for_a_real_identity(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert [str(n.resource_id) for n in find_resources_using_identity(
            exposure_graph, ResourceId("role/app"), identity_types=["iam_role", "iam_user"]
        )] == ["i-web"]

    def test_a_resource_using_an_identity_twice_is_reported_once(self) -> None:
        graph = build(
            [node("vm-1", "azure_vm"), node("mi-1", "managed_identity")],
            [edge("vm-1", "mi-1", RT.ACCESSES), edge("vm-1", "mi-1", RT.ASSUMES)],
        )
        assert len(find_resources_using_identity(graph, ResourceId("mi-1"))) == 1


class TestAbsenceQueries:
    """The control class the existence-quantified DSL cannot express."""

    def test_reports_resources_with_no_edge_of_the_relationship(
        self, exposure_graph: ResourceGraph
    ) -> None:
        # sg-open exposes to the internet; sg-closed does not.
        assert [str(n.resource_id) for n in find_resources_without_relationship(
            exposure_graph,
            resource_type="security_group",
            relationship_type=RT.PUBLICLY_EXPOSED,
        )] == ["sg-closed"]

    def test_a_resource_with_a_different_relationship_still_counts_as_absent(self) -> None:
        graph = build(
            [node("db-1", "azure_sql"), node("vnet-1", "azure_vnet")],
            [edge("db-1", "vnet-1", RT.ATTACHED_TO)],
        )
        # ATTACHED_TO is not CONNECTS_TO. "Has some relationship" must
        # never be read as "has the required relationship".
        assert [str(n.resource_id) for n in find_resources_without_relationship(
            graph, resource_type="azure_sql", relationship_type=RT.CONNECTS_TO
        )] == ["db-1"]

    def test_direction_is_respected(self) -> None:
        graph = build(
            [node("db-1", "azure_sql"), node("pe-1", "private_endpoint")],
            [edge("pe-1", "db-1", RT.CONNECTS_TO)],
        )
        # The endpoint points at the database, so outgoing is absent...
        assert [str(n.resource_id) for n in find_resources_without_relationship(
            graph,
            resource_type="azure_sql",
            relationship_type=RT.CONNECTS_TO,
            direction="outgoing",
        )] == ["db-1"]
        # ...while incoming is present.
        assert find_resources_without_relationship(
            graph,
            resource_type="azure_sql",
            relationship_type=RT.CONNECTS_TO,
            direction="incoming",
        ) == ()

    def test_absence_is_indistinguishable_from_a_data_gap(self) -> None:
        """Pins the caveat in the function's docstring.

        A graph where the private-endpoint collector never ran looks
        EXACTLY like a graph where no private endpoint exists. This test
        does not assert a defect — it asserts that the function cannot
        tell the difference, which is why a rule built on it must gate on
        evidence that the relevant collector actually ran.
        """

        never_collected = build([node("db-1", "azure_sql")], [])
        genuinely_absent = build(
            [node("db-1", "azure_sql"), node("pe-1", "private_endpoint")],
            [],
        )
        query = dict(resource_type="azure_sql", relationship_type=RT.CONNECTS_TO)
        assert [
            str(n.resource_id) for n in find_resources_without_relationship(
                never_collected, **query  # type: ignore[arg-type]
            )
        ] == [
            str(n.resource_id) for n in find_resources_without_relationship(
                genuinely_absent, **query  # type: ignore[arg-type]
            )
        ]

    def test_no_resources_of_the_type_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert find_resources_without_relationship(
            exposure_graph, resource_type="rds_instance", relationship_type=RT.CONNECTS_TO
        ) == ()


class TestGraphStatistics:
    def test_counts_nodes_edges_and_external_nodes(self, exposure_graph: ResourceGraph) -> None:
        stats = graph_statistics(exposure_graph)
        assert stats["nodes"] == 6
        assert stats["edges"] == 5
        assert stats["external_nodes"] == 1

    def test_splits_by_provider_so_a_silent_cloud_is_visible(self) -> None:
        # "183 nodes" says nothing about whether the Azure half of a
        # multi-cloud scan collected anything.
        graph = build(
            [
                node("i-1", "ec2_instance", provider=CloudProvider.AWS),
                node("vm-1", "azure_vm", provider=CloudProvider.AZURE),
            ],
            [],
        )
        stats = graph_statistics(graph)
        assert stats["by_provider"]["aws"]["nodes"] == 1
        assert stats["by_provider"]["azure"]["nodes"] == 1

    def test_external_nodes_are_bucketed_separately_from_a_provider(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert graph_statistics(exposure_graph)["by_provider"]["external"]["nodes"] == 1

    def test_counts_by_resource_type_and_relationship(
        self, exposure_graph: ResourceGraph
    ) -> None:
        stats = graph_statistics(exposure_graph)
        assert stats["by_resource_type"]["security_group"] == 2
        assert stats["by_relationship"]["attached_to"] == 2

    def test_output_is_deterministic_across_insertion_orders(self) -> None:
        nodes = [node("a", "s3_bucket"), node("b", "iam_role"), node("c", "ec2_instance")]
        first = build(nodes[:], [edge("c", "b", RT.ASSUMES), edge("b", "a", RT.ACCESSES)])
        second = build(
            [nodes[2], nodes[0], nodes[1]],
            [edge("b", "a", RT.ACCESSES), edge("c", "b", RT.ASSUMES)],
        )
        assert graph_statistics(first) == graph_statistics(second)
        # Equality is not enough — key ORDER must match too, so a
        # serialized report is byte-identical between runs.
        assert list(graph_statistics(first)["by_resource_type"]) == list(
            graph_statistics(second)["by_resource_type"]
        )

    def test_empty_graph_reports_zeros_rather_than_failing(self) -> None:
        stats = graph_statistics(ResourceGraph(tenant_id=TENANT))
        assert stats["nodes"] == 0
        assert stats["edges"] == 0
        assert stats["by_provider"] == {}


class TestIterEdges:
    def test_yields_every_edge_in_deterministic_order(self) -> None:
        nodes = [node("a"), node("b"), node("c")]
        first = build(nodes[:], [edge("a", "b", RT.ACCESSES), edge("a", "c", RT.ACCESSES)])
        second = build(nodes[:], [edge("a", "c", RT.ACCESSES), edge("a", "b", RT.ACCESSES)])
        assert [e.identity for e in iter_edges(first)] == [e.identity for e in iter_edges(second)]
        assert len(list(iter_edges(first))) == 2


class TestNeighborsStillBehavesTheSame:
    """``ResourceGraph.neighbors`` was migrated from a linear scan to the
    adjacency indexes. Its observable contract must not have changed.
    """

    def test_outgoing_matches_a_linear_scan(self, exposure_graph: ResourceGraph) -> None:
        scanned = [
            exposure_graph.get_node(e.target_id)
            for e in exposure_graph.edges
            if e.source_id == ResourceId("i-web") and e.relationship_type == RT.ATTACHED_TO
        ]
        assert list(
            exposure_graph.neighbors(
                ResourceId("i-web"), RT.ATTACHED_TO, direction="outgoing"
            )
        ) == scanned

    def test_incoming_matches_a_linear_scan(self, exposure_graph: ResourceGraph) -> None:
        scanned = [
            exposure_graph.get_node(e.source_id)
            for e in exposure_graph.edges
            if e.target_id == ResourceId("sg-open") and e.relationship_type == RT.ATTACHED_TO
        ]
        assert list(
            exposure_graph.neighbors(
                ResourceId("sg-open"), RT.ATTACHED_TO, direction="incoming"
            )
        ) == scanned

    def test_unknown_resource_still_returns_empty(self, exposure_graph: ResourceGraph) -> None:
        assert exposure_graph.neighbors(
            ResourceId("nope"), RT.ATTACHED_TO, direction="outgoing"
        ) == ()

    def test_index_readers_reject_nothing_and_return_tuples(
        self, exposure_graph: ResourceGraph
    ) -> None:
        assert exposure_graph.outgoing_edges(ResourceId("nope")) == ()
        assert exposure_graph.incoming_edges(ResourceId("nope")) == ()
        assert exposure_graph.resource_ids_of_type("nope") == ()

    def test_index_readers_hand_out_copies_not_live_lists(
        self, exposure_graph: ResourceGraph
    ) -> None:
        # An index is internal accounting. Handing out the live list
        # would let a caller corrupt it without going through add_edge.
        before = exposure_graph.outgoing_edges(ResourceId("i-web"))
        assert isinstance(before, tuple)
        assert exposure_graph.outgoing_edges(ResourceId("i-web")) == before


class TestQueriesDoNotMutate:
    def test_a_full_query_sweep_leaves_the_graph_unchanged(
        self, exposure_graph: ResourceGraph
    ) -> None:
        before_nodes = exposure_graph.nodes
        before_edges = exposure_graph.edges

        edges_of(exposure_graph, ResourceId("i-web"))
        related_nodes(exposure_graph, ResourceId("i-web"))
        find_resources(exposure_graph, "security_group")
        find_paths(exposure_graph, source=ResourceId("i-web"), target=ResourceId("bucket-data"))
        find_resources_exposed_to_internet(exposure_graph)
        find_resources_using_identity(exposure_graph, ResourceId("role/app"))
        find_resources_without_relationship(
            exposure_graph, resource_type="security_group", relationship_type=RT.CONNECTS_TO
        )
        graph_statistics(exposure_graph)
        list(iter_edges(exposure_graph))

        assert exposure_graph.nodes == before_nodes
        assert exposure_graph.edges == before_edges

    def test_get_node_still_raises_for_an_unknown_id(
        self, exposure_graph: ResourceGraph
    ) -> None:
        with pytest.raises(GraphIntegrityViolation):
            exposure_graph.get_node(ResourceId("nope"))
