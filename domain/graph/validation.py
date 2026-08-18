"""Resource Graph validation (expansion §8).

`ResourceGraph` already enforces its hard invariants at construction —
tenant isolation, referential integrity, duplicate nodes — by *raising*.
That is right for a corrupt graph, and wrong for everything else: a
scan should not die because two collectors disagreed about a region.

So this module is **diagnostic, not fatal**. It inspects a built graph
and returns findings the caller can log, surface as scan warnings, or
assert on in tests. The distinction matters:

* `add_node`/`add_edge` raising = "this graph is not constructible"
* validation = "this graph is constructible but suspicious"

The second class is the more common one in production, and it is exactly
what nobody notices without a report. A cross-resource rule that quietly
stops firing because an edge was dropped looks identical to a rule that
found nothing wrong.

§8 also requires **determinism**: identical cloud input must produce an
equivalent graph. `graph_fingerprint` makes that assertable rather than
aspirational.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.shared.enums import RelationshipType


class Severity(str, Enum):
    """How much a validation finding matters."""

    #: The graph is wrong and rules over it will be wrong.
    ERROR = "error"
    #: The graph is usable but something is likely misconfigured.
    WARNING = "warning"
    #: Worth knowing, expected in normal operation.
    INFO = "info"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    severity: Severity
    message: str
    subject: str | None = None


#: Relationships that make no sense between certain node types. Kept
#: deliberately small: every entry must be a genuine impossibility, not
#: merely unusual. A false "impossible relationship" would suppress a
#: real edge and silently disable whatever rule depended on it.
_IMPOSSIBLE: dict[RelationshipType, frozenset[str]] = {
    # The internet cannot assume a role or be attached to anything; it is
    # only ever a TARGET of exposure.
    RelationshipType.ASSUMES: frozenset({"internet"}),
    RelationshipType.ATTACHED_TO: frozenset({"internet"}),
}


@dataclass(frozen=True, slots=True)
class ValidationReport:
    issues: tuple[ValidationIssue, ...] = ()
    node_count: int = 0
    edge_count: int = 0
    external_node_count: int = 0
    relationship_counts: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity is Severity.ERROR)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity is Severity.WARNING)

    @property
    def is_valid(self) -> bool:
        """No ERRORs. Warnings are expected in a healthy graph."""

        return not self.errors


def validate_graph(graph: ResourceGraph) -> ValidationReport:
    """Inspect a built graph and report structural problems."""

    issues: list[ValidationIssue] = []
    nodes = {node.resource_id: node for node in graph.nodes}
    external = [n for n in graph.nodes if n.is_external]

    # --- Dangling references.
    #
    # ResourceGraph.add_edge already prevents these, so a hit here means
    # the graph was assembled by some other path. Checked anyway: this
    # module's job is to be true about the graph it is given, not to
    # assume how it was built.
    for edge in graph.edges:
        for role, node_id in (("source", edge.source_id), ("target", edge.target_id)):
            if node_id not in nodes:
                issues.append(
                    ValidationIssue(
                        code="dangling_edge",
                        severity=Severity.ERROR,
                        message=f"edge {role} references a node not in the graph",
                        subject=str(node_id),
                    )
                )

    # --- Duplicate edges.
    #
    # Not fatal — two collectors observing the same relationship is
    # normal — but a large count usually means a collector is emitting
    # the same edge per page, which inflates graph size.
    edge_identities = Counter(edge.identity for edge in graph.edges)
    for identity, count in edge_identities.items():
        if count > 1:
            source, target, relationship = identity
            issues.append(
                ValidationIssue(
                    code="duplicate_edge",
                    severity=Severity.WARNING,
                    message=f"{relationship.value} asserted {count} times",
                    subject=f"{source!s} -> {target!s}",
                )
            )

    # --- Self-loops.
    for edge in graph.edges:
        if edge.source_id == edge.target_id:
            issues.append(
                ValidationIssue(
                    code="self_loop",
                    severity=Severity.WARNING,
                    message=f"resource relates to itself via {edge.relationship_type.value}",
                    subject=str(edge.source_id),
                )
            )

    # --- Cross-account edges.
    #
    # Legitimate and important (a role trusting a partner account is a
    # real, intended pattern), so INFO not ERROR. Surfaced because it is
    # exactly what a cross-account rule wants to reason about, and
    # because an UNEXPECTED one is worth a human look.
    for edge in graph.edges:
        source = nodes.get(edge.source_id)
        target = nodes.get(edge.target_id)
        if source is None or target is None:
            continue
        if target.is_external or source.is_external:
            continue
        if (
            source.account_id
            and target.account_id
            and source.account_id != target.account_id
        ):
            issues.append(
                ValidationIssue(
                    code="cross_account_edge",
                    severity=Severity.INFO,
                    message=(
                        f"{edge.relationship_type.value} crosses accounts "
                        f"{source.account_id} -> {target.account_id}"
                    ),
                    subject=f"{edge.source_id!s} -> {edge.target_id!s}",
                )
            )

    # --- Impossible relationships.
    for edge in graph.edges:
        target = nodes.get(edge.target_id)
        if target is None:
            continue
        forbidden = _IMPOSSIBLE.get(edge.relationship_type)
        if forbidden and target.resource_type in forbidden:
            issues.append(
                ValidationIssue(
                    code="impossible_relationship",
                    severity=Severity.ERROR,
                    message=(
                        f"{edge.relationship_type.value} cannot target "
                        f"a {target.resource_type} node"
                    ),
                    subject=f"{edge.source_id!s} -> {edge.target_id!s}",
                )
            )

    # --- Orphan external nodes.
    #
    # An external node exists only because something pointed at it. One
    # with no inbound edge means the relationship that created it was
    # dropped — a silent loss of exactly the signal cross-resource rules
    # depend on.
    referenced = {edge.target_id for edge in graph.edges} | {
        edge.source_id for edge in graph.edges
    }
    for node in external:
        if node.resource_id not in referenced:
            issues.append(
                ValidationIssue(
                    code="orphan_external_node",
                    severity=Severity.WARNING,
                    message="external node has no edges; the relationship that created it was lost",
                    subject=str(node.resource_id),
                )
            )

    return ValidationReport(
        issues=tuple(issues),
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        external_node_count=len(external),
        relationship_counts=dict(
            Counter(edge.relationship_type.value for edge in graph.edges)
        ),
    )


def graph_fingerprint(graph: ResourceGraph) -> str:
    """A stable hash of the graph's structure (§8 determinism).

    Identical cloud input must produce an equivalent graph. "Equivalent"
    is not "identical object", so equality is defined here explicitly:

    * nodes and edges are **sorted**, because insertion order reflects
      collector scheduling and carries no meaning
    * **provenance is excluded** — `source_collector` and `confidence`
      describe how we learned something, not what is true. Two scans
      that learn the same topology from different collectors describe
      the same infrastructure.
    * **evidence is excluded** for the same reason

    So a changed fingerprint means the *topology* changed, which is a
    real signal, rather than that a collector ran in a different order,
    which is noise.
    """

    payload = {
        "tenant": str(graph.tenant_id),
        "nodes": sorted(
            [str(node.resource_id), node.resource_type, node.kind]
            for node in graph.nodes
        ),
        "edges": sorted(
            [str(e.source_id), str(e.target_id), e.relationship_type.value, str(e.blocked)]
            for e in graph.edges
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def graph_context_for(graph: ResourceGraph, resource_id) -> dict:
    """The neighbourhood of one resource, for finding enrichment (§11).

    This is what turns "S3 bucket is public" into a contextual finding:
    the AI Copilot and the dashboard both need to know what the resource
    is connected to, and re-deriving it from the raw resource list at
    render time would be both slow and inconsistent.

    Deterministic ordering, so two runs over the same graph produce
    byte-identical context.
    """

    outgoing = [
        {
            "relationship": e.relationship_type.value,
            "target": str(e.target_id),
            "target_type": (
                graph.get_node(e.target_id).resource_type
                if graph.has_node(e.target_id)
                else None
            ),
            "confidence": e.confidence,
            "evidence": dict(e.evidence),
        }
        for e in graph.edges
        if e.source_id == resource_id
    ]
    incoming = [
        {
            "relationship": e.relationship_type.value,
            "source": str(e.source_id),
            "source_type": (
                graph.get_node(e.source_id).resource_type
                if graph.has_node(e.source_id)
                else None
            ),
            "confidence": e.confidence,
        }
        for e in graph.edges
        if e.target_id == resource_id
    ]

    return {
        "outgoing": sorted(outgoing, key=lambda r: (r["relationship"], r["target"])),
        "incoming": sorted(incoming, key=lambda r: (r["relationship"], r["source"])),
        "is_internet_exposed": any(
            e.relationship_type is RelationshipType.PUBLICLY_EXPOSED
            for e in graph.edges
            if e.source_id == resource_id
        ),
    }


__all__ = [
    "GraphEdge",
    "GraphNode",
    "Severity",
    "ValidationIssue",
    "ValidationReport",
    "graph_context_for",
    "graph_fingerprint",
    "validate_graph",
]
