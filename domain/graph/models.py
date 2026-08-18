"""The Resource Graph (blueprint §10).

``ResourceGraph`` is a tenant-scoped aggregate: it owns its nodes and
edges, enforces tenant isolation at ``add_node``, and enforces
referential integrity at ``add_edge`` (an edge can never reference a node
that does not exist). Nobody mutates it after a scan builds it — there is
no incremental-mutation API beyond ``add_node``/``add_edge`` themselves,
matching blueprint §10 ("qui le mute: personne après construction").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Mapping

from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import GraphIntegrityViolation
from domain.shared.identifiers import ResourceId, TenantId
from domain.tenants.isolation import ensure_same_tenant


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A resource represented inside a ``ResourceGraph``."""

    resource_id: ResourceId
    tenant_id: TenantId
    resource_type: str

    # --- Provenance and context (expansion §7). Every field is optional
    # so the three-argument constructor used throughout Phases 1-5 keeps
    # working unchanged.

    #: Cloud provider. Optional because EXTERNAL nodes (the internet, a
    #: foreign account) belong to no provider we scanned.
    provider: "CloudProvider | None" = None
    #: Human-readable name for reports. The resource_id is often an ARN.
    name: str | None = None
    #: AWS account id / Azure subscription id.
    account_id: str | None = None
    region: str | None = None
    #: Which collector asserted this node. Provenance: when two
    #: collectors disagree, or a relationship is disputed, this is the
    #: only way to know who said what.
    source_collector: str | None = None
    #: How much to trust this node's existence and attributes.
    confidence: str = "high"
    #: What KIND of node this is. The distinction that fixes the blocker
    #: (audit E1): a COLLECTED node is a real resource we enumerated; an
    #: EXTERNAL node is a legitimate edge target that is not a
    #: collectible resource — the internet, an AWS service principal, a
    #: foreign account. Without it, collectors must either drop those
    #: edges (losing the signal) or emit them and abort the scan.
    kind: str = "collected"

    def __post_init__(self) -> None:
        if not isinstance(self.resource_type, str) or not self.resource_type.strip():
            raise GraphIntegrityViolation("GraphNode.resource_type must be a non-blank string")
        if self.kind not in ("collected", "external"):
            raise GraphIntegrityViolation(
                f"GraphNode.kind must be 'collected' or 'external', got {self.kind!r}"
            )
        if self.confidence not in ("high", "medium", "low", "unknown"):
            raise GraphIntegrityViolation(
                f"GraphNode.confidence must be high/medium/low/unknown, got {self.confidence!r}"
            )

    @property
    def is_external(self) -> bool:
        """Whether this node represents something outside the scan.

        Rules must be able to tell the difference. "This role trusts an
        external account" is a finding; "this role trusts a node we
        happen not to have collected" is a data gap, and conflating them
        produces confident findings about resources nobody enumerated.
        """

        return self.kind == "external"


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A directed relationship between two nodes, using the closed
    ``RelationshipType`` vocabulary (blueprint §10). ``blocked`` records
    whether the relationship is prevented in practice (e.g. a security
    group rule that denies rather than allows) — attack path discovery
    relies on this flag.
    """

    source_id: ResourceId
    target_id: ResourceId
    relationship_type: RelationshipType
    blocked: bool = False

    # --- Provenance (expansion §7). Optional, so every existing
    # four-argument construction keeps working.

    #: WHY the graph believes this edge exists — the specific observed
    #: facts. Without it an edge is an unattributable assertion, and a
    #: cross-resource finding cannot show its reasoning. Kept as a small
    #: mapping of collected values, never free prose.
    evidence: Mapping[str, Any] = field(default_factory=dict)
    #: Which collector asserted this relationship.
    source_collector: str | None = None
    confidence: str = "high"

    def __post_init__(self) -> None:
        if not isinstance(self.relationship_type, RelationshipType):
            raise GraphIntegrityViolation(
                f"relationship_type must be a RelationshipType, got {self.relationship_type!r}"
            )
        if self.confidence not in ("high", "medium", "low", "unknown"):
            raise GraphIntegrityViolation(
                f"GraphEdge.confidence must be high/medium/low/unknown, got {self.confidence!r}"
            )
        if not isinstance(self.evidence, Mapping):
            raise GraphIntegrityViolation("GraphEdge.evidence must be a mapping")
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    @property
    def identity(self) -> tuple:
        """What makes this edge a duplicate of another.

        Provenance is excluded on purpose: two collectors independently
        observing the same relationship assert the SAME edge, not two.
        """

        return (self.source_id, self.target_id, self.relationship_type)


@dataclass(slots=True)
class ResourceGraph:
    """A tenant-scoped, in-memory resource graph.

    Lives for the duration of a single scan (blueprint §10: rebuilt every
    time, never persisted in the Domain). Not frozen — it is a mutable
    aggregate built incrementally by its owner, but every mutation goes
    through an invariant-checking method.
    """

    tenant_id: TenantId
    _nodes: dict[ResourceId, GraphNode] = field(default_factory=dict, repr=False)
    _edges: list[GraphEdge] = field(default_factory=list, repr=False)

    # --- Indexes (expansion §15).
    #
    # Every relationship query was previously a linear scan of _edges, so
    # evaluating R relationship rules over N resources cost O(R x N x E).
    # Adequate at 183 nodes; not at 1000.
    #
    # Maintained INSIDE add_node/add_edge rather than rebuilt on demand,
    # so an index can never disagree with the authoritative collection —
    # a stale index would make a rule silently stop firing, which is
    # indistinguishable from the rule finding nothing.
    _out: dict[ResourceId, list[GraphEdge]] = field(default_factory=dict, repr=False)
    _in: dict[ResourceId, list[GraphEdge]] = field(default_factory=dict, repr=False)
    _by_type: dict[str, list[ResourceId]] = field(default_factory=dict, repr=False)

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges)

    def has_node(self, resource_id: ResourceId) -> bool:
        return resource_id in self._nodes

    def get_node(self, resource_id: ResourceId) -> GraphNode:
        try:
            return self._nodes[resource_id]
        except KeyError:
            raise GraphIntegrityViolation(f"no node for resource_id {resource_id!s}") from None

    def add_node(self, node: GraphNode) -> None:
        ensure_same_tenant(self.tenant_id, node.tenant_id, context="graph node")
        if node.resource_id in self._nodes:
            raise GraphIntegrityViolation(
                f"duplicate node: {node.resource_id!s} is already present in this graph"
            )
        self._nodes[node.resource_id] = node
        self._by_type.setdefault(node.resource_type, []).append(node.resource_id)

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_id not in self._nodes:
            raise GraphIntegrityViolation(
                f"edge references unknown source node: {edge.source_id!s}"
            )
        if edge.target_id not in self._nodes:
            raise GraphIntegrityViolation(
                f"edge references unknown target node: {edge.target_id!s}"
            )
        self._edges.append(edge)
        self._out.setdefault(edge.source_id, []).append(edge)
        self._in.setdefault(edge.target_id, []).append(edge)

    # --- Index readers.
    #
    # Public so that query code (``domain.graph.queries``) never reaches
    # into the private collections. They return tuples: an index is an
    # internal accounting structure, and handing out the live list would
    # let a caller corrupt it without going through add_edge.

    def outgoing_edges(self, resource_id: ResourceId) -> tuple[GraphEdge, ...]:
        """Edges whose source is ``resource_id``, in insertion order."""

        return tuple(self._out.get(resource_id, ()))

    def incoming_edges(self, resource_id: ResourceId) -> tuple[GraphEdge, ...]:
        """Edges whose target is ``resource_id``, in insertion order."""

        return tuple(self._in.get(resource_id, ()))

    def resource_ids_of_type(self, resource_type: str) -> tuple[ResourceId, ...]:
        """Ids of every node of ``resource_type``, in insertion order."""

        return tuple(self._by_type.get(resource_type, ()))

    def neighbors(
        self,
        resource_id: ResourceId,
        relationship_type: RelationshipType,
        *,
        direction: Literal["outgoing", "incoming"],
    ) -> tuple[GraphNode, ...]:
        """Nodes directly connected to ``resource_id`` by an edge of
        exactly ``relationship_type``, in the given ``direction``.

        Read-only, one hop only — deliberately not a general traversal
        API (no path-finding, no depth parameter). An unknown
        ``resource_id`` or a node with no matching edges both return an
        empty tuple, never an error: "no relationship exists" is a
        determinate fact about the graph, not a failure.

        Index-backed since the expansion (§15). The observable behaviour
        is unchanged — the adjacency lists preserve edge insertion order,
        so this returns exactly what the previous linear scan returned,
        in the same order.
        """

        edges = (
            self.outgoing_edges(resource_id)
            if direction == "outgoing"
            else self.incoming_edges(resource_id)
        )
        matches = (
            (e.target_id if direction == "outgoing" else e.source_id)
            for e in edges
            if e.relationship_type == relationship_type
        )
        return tuple(self._nodes[node_id] for node_id in matches if node_id in self._nodes)
