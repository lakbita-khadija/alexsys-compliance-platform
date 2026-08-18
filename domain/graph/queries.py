"""Graph query primitives for CSPM reasoning (expansion §1.6).

Deliberately **not** a general graph library. §1.6 says "implement only
the primitives really needed by the CSPM", and that constraint is load
bearing: every query here answers a question a security rule actually
asks, and a general traversal API would invite rules that are slow,
non-deterministic, or both.

Three properties every function guarantees:

**Index-backed.** Queries use the adjacency and type indexes maintained
inside `ResourceGraph.add_node`/`add_edge`, not linear scans. Relationship
evaluation was O(R × N × E); it is now proportional to the neighbourhood
actually touched.

**Deterministic ordering.** Every function that returns a collection
sorts it. Insertion order reflects collector scheduling, which is not a
property of the customer's infrastructure, and a finding whose evidence
lists resources in a different order on every scan is a finding nobody
can diff.

**Absence is expressible.** `find_resources_without_relationship` exists
because "critical resource with **no** private endpoint" and "resource
with **no** diagnostic settings" are real, high-value controls that the
existence-quantified `relationship` condition cannot express. Absence is
also where a data gap is most dangerous — see the note on that function.
"""

from __future__ import annotations

from typing import Iterable, Iterator, Literal

from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId

Direction = Literal["outgoing", "incoming"]

#: Relationship types that mean "reachable from outside". Used by the
#: exposure queries so "public" has one definition instead of each rule
#: inventing its own.
_EXPOSURE_RELATIONSHIPS = (RelationshipType.PUBLICLY_EXPOSED,)

#: Identifier of the synthetic node representing the public internet.
INTERNET = ResourceId("internet")


def _sorted_nodes(nodes: Iterable[GraphNode]) -> tuple[GraphNode, ...]:
    return tuple(sorted(nodes, key=lambda n: str(n.resource_id)))


def _sorted_edges(edges: Iterable[GraphEdge]) -> tuple[GraphEdge, ...]:
    return tuple(
        sorted(
            edges,
            key=lambda e: (str(e.source_id), str(e.target_id), e.relationship_type.value),
        )
    )


def edges_of(
    graph: ResourceGraph,
    resource_id: ResourceId,
    *,
    direction: Direction = "outgoing",
    relationship_type: RelationshipType | None = None,
) -> tuple[GraphEdge, ...]:
    """Edges touching ``resource_id``, index-backed and ordered.

    The primitive the rest of this module is built on. ``relationship_type``
    is optional — unlike ``ResourceGraph.neighbors``, which requires an
    exact type and therefore cannot answer "what is this connected to at
    all?".
    """

    edges: Iterable[GraphEdge] = (
        graph.outgoing_edges(resource_id)
        if direction == "outgoing"
        else graph.incoming_edges(resource_id)
    )
    if relationship_type is not None:
        edges = [e for e in edges if e.relationship_type is relationship_type]
    return _sorted_edges(edges)


def related_nodes(
    graph: ResourceGraph,
    resource_id: ResourceId,
    *,
    direction: Direction = "outgoing",
    relationship_type: RelationshipType | None = None,
    target_type: str | None = None,
) -> tuple[GraphNode, ...]:
    """Nodes one hop from ``resource_id``.

    Unknown resource ids and resources with no matching edges both return
    an empty tuple rather than raising: "no relationship exists" is a
    determinate fact about the graph, not a failure.
    """

    nodes = []
    for edge in edges_of(
        graph, resource_id, direction=direction, relationship_type=relationship_type
    ):
        other = edge.target_id if direction == "outgoing" else edge.source_id
        if not graph.has_node(other):
            continue
        node = graph.get_node(other)
        if target_type is not None and node.resource_type != target_type:
            continue
        nodes.append(node)
    return _sorted_nodes(nodes)


def find_resources(graph: ResourceGraph, resource_type: str) -> tuple[GraphNode, ...]:
    """Every node of one type. Index-backed, not a scan."""

    return _sorted_nodes(
        graph.get_node(rid) for rid in graph.resource_ids_of_type(resource_type)
    )


def has_relationship(
    graph: ResourceGraph,
    *,
    source: ResourceId,
    relationship_type: RelationshipType,
    target: ResourceId,
) -> bool:
    """Whether one specific edge exists."""

    return any(
        e.target_id == target
        for e in edges_of(graph, source, relationship_type=relationship_type)
    )


def find_paths(
    graph: ResourceGraph,
    *,
    source: ResourceId,
    target: ResourceId,
    max_depth: int = 4,
    include_blocked: bool = False,
) -> tuple[tuple[GraphEdge, ...], ...]:
    """Every simple path from ``source`` to ``target`` up to ``max_depth``.

    Depth-bounded and cycle-free by construction. ``max_depth`` is not a
    performance knob to be raised casually — path count grows
    combinatorially, and an unbounded search over a large tenant's graph
    is a denial of service against our own scanner. Four hops covers the
    exposure chains a CSPM reasons about (internet → LB → instance → role
    → data).

    ``blocked`` edges are excluded by default: an edge marked blocked is
    a relationship that exists structurally but is prevented in practice,
    and including it would report attack paths that cannot be walked.

    Results are sorted, so two runs over the same graph return paths in
    the same order.
    """

    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")

    results: list[tuple[GraphEdge, ...]] = []

    def walk(
        current: ResourceId,
        path: tuple[GraphEdge, ...],
        visited: frozenset[ResourceId],
    ) -> None:
        if len(path) >= max_depth:
            return
        for edge in edges_of(graph, current):
            if edge.blocked and not include_blocked:
                continue
            nxt = edge.target_id
            if nxt in visited:
                continue  # no cycles; a simple path visits each node once
            extended = path + (edge,)
            if nxt == target:
                results.append(extended)
                continue
            walk(nxt, extended, visited | {nxt})

    walk(source, (), frozenset({source}))
    return tuple(sorted(results, key=lambda p: (len(p), [str(e.target_id) for e in p])))


def internet_node_ids(graph: ResourceGraph) -> tuple[ResourceId, ...]:
    """Ids of every node standing for the public internet.

    Two sources, because the identifier is a collector convention and the
    type is a graph-builder classification, and a query that trusted only
    one of them would silently miss exposure:

    - the conventional id ``internet`` that collectors emit, and
    - any node the builder classified as ``resource_type="internet"``.
    """

    ids = set(graph.resource_ids_of_type("internet"))
    if graph.has_node(INTERNET):
        ids.add(INTERNET)
    return tuple(sorted(ids, key=str))


def find_resources_exposed_to_internet(graph: ResourceGraph) -> tuple[GraphNode, ...]:
    """Resources with a direct exposure edge to the internet.

    Direct only — one hop. Transitive reachability is what ``find_paths``
    is for, and conflating the two would let a rule claim direct exposure
    for a resource three hops away.

    ``blocked`` edges are excluded: an exposure relationship that is
    prevented in practice is not exposure, and reporting it as such is a
    false positive on the single highest-severity signal a CSPM emits.
    """

    exposed: set[GraphNode] = set()
    for internet in internet_node_ids(graph):
        for relationship in _EXPOSURE_RELATIONSHIPS:
            for edge in edges_of(
                graph, internet, direction="incoming", relationship_type=relationship
            ):
                if edge.blocked:
                    continue
                if graph.has_node(edge.source_id):
                    exposed.add(graph.get_node(edge.source_id))
    return _sorted_nodes(exposed)


def find_resources_using_identity(
    graph: ResourceGraph,
    identity: ResourceId,
    *,
    identity_types: Iterable[str] | None = None,
) -> tuple[GraphNode, ...]:
    """Resources that assume or otherwise use an identity.

    "Which workloads run as this over-privileged role?" — the question
    behind every privilege-escalation finding.

    **Caller contract, and why it is a contract rather than a check.**
    `ASSUMES` is only ever emitted toward an identity, but `ACCESSES` is
    not: a role accessing a bucket uses the same relationship type as a
    VM using a managed identity. So passing a *data* resource here
    returns its readers, which is a true statement about the graph and a
    misleading answer to the question the function's name asks.

    The domain deliberately does not hardcode a list of "identity
    resource types" to guard against that. Only `iam_role` and `iam_user`
    exist today — `managed_identity` and `service_principal` need Entra
    ID collectors that are not written — so such a list would be a
    vocabulary invented ahead of the collectors that produce it, and
    would silently exclude every identity added later.

    Instead ``identity_types`` lets a caller that *does* know the
    vocabulary opt into the guard: pass the types it considers
    identities and a non-identity target yields an empty result rather
    than a plausible wrong one.
    """

    if identity_types is not None:
        if not graph.has_node(identity):
            return ()
        if graph.get_node(identity).resource_type not in set(identity_types):
            return ()

    users: set[GraphNode] = set()
    for relationship in (RelationshipType.ASSUMES, RelationshipType.ACCESSES):
        for edge in edges_of(
            graph, identity, direction="incoming", relationship_type=relationship
        ):
            if graph.has_node(edge.source_id):
                users.add(graph.get_node(edge.source_id))
    return _sorted_nodes(users)


def find_resources_without_relationship(
    graph: ResourceGraph,
    *,
    resource_type: str,
    relationship_type: RelationshipType,
    direction: Direction = "outgoing",
) -> tuple[GraphNode, ...]:
    """Resources of a type that have NO edge of a given relationship.

    Unlocks the control class the existence-quantified `relationship`
    condition cannot express: *critical resource with no private
    endpoint*, *resource with no diagnostic settings*.

    **Read the caveat.** Absence in the graph means "not observed", which
    is not the same as "does not exist". If a collector lacked permission
    to enumerate private endpoints, every resource looks like it has
    none, and this query would report the entire estate as
    non-compliant — a mass false positive.

    A rule built on this must therefore gate on evidence that the
    relevant collector actually ran, exactly as the finding-lifecycle
    resolution logic gates on `covered_resources`. This function reports
    graph structure; it cannot know why an edge is missing.
    """

    return _sorted_nodes(
        node
        for node in find_resources(graph, resource_type)
        if not edges_of(
            graph, node.resource_id, direction=direction, relationship_type=relationship_type
        )
    )


def graph_statistics(graph: ResourceGraph) -> dict:
    """Counts for observability (§1.5, §18).

    Split by provider and by node kind, because "183 nodes" says nothing
    about whether the Azure half of a multi-cloud scan collected
    anything.
    """

    stats: dict = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "external_nodes": sum(1 for n in graph.nodes if n.is_external),
        "by_provider": {},
        "by_resource_type": {},
        "by_relationship": {},
    }

    for node in graph.nodes:
        provider = node.provider.value if node.provider else "external"
        bucket = stats["by_provider"].setdefault(provider, {"nodes": 0, "edges": 0})
        bucket["nodes"] += 1
        stats["by_resource_type"][node.resource_type] = (
            stats["by_resource_type"].get(node.resource_type, 0) + 1
        )

    for edge in graph.edges:
        stats["by_relationship"][edge.relationship_type.value] = (
            stats["by_relationship"].get(edge.relationship_type.value, 0) + 1
        )
        if graph.has_node(edge.source_id):
            source = graph.get_node(edge.source_id)
            provider = source.provider.value if source.provider else "external"
            stats["by_provider"].setdefault(provider, {"nodes": 0, "edges": 0})["edges"] += 1

    # Sorted so two runs produce byte-identical output.
    stats["by_resource_type"] = dict(sorted(stats["by_resource_type"].items()))
    stats["by_relationship"] = dict(sorted(stats["by_relationship"].items()))
    stats["by_provider"] = dict(sorted(stats["by_provider"].items()))
    return stats


def iter_edges(graph: ResourceGraph) -> Iterator[GraphEdge]:
    """Deterministically ordered iteration over every edge."""

    return iter(_sorted_edges(graph.edges))


__all__ = [
    "INTERNET",
    "Direction",
    "edges_of",
    "find_paths",
    "find_resources",
    "find_resources_exposed_to_internet",
    "find_resources_using_identity",
    "find_resources_without_relationship",
    "graph_statistics",
    "has_relationship",
    "internet_node_ids",
    "iter_edges",
    "related_nodes",
]
