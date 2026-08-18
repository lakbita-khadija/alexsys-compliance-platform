"""``BuildResourceGraph`` (blueprint §4, formalizing the informal
``GraphBuilder.build()`` described in §10).

Pure orchestration: constructs a ``domain.graph.ResourceGraph`` from a
collection of ``NormalizedResource``s using only the Domain's own
``add_node``/``add_edge`` methods. Every invariant (tenant isolation,
referential integrity, closed relationship vocabulary) is enforced by
the Domain itself and surfaces here unmodified — this class adds no
validation of its own, per blueprint §10 ("qui le mute: personne après
construction") and the instruction not to duplicate Domain invariants.
"""

from __future__ import annotations

from typing import Iterable

from dataclasses import dataclass

from domain.graph.identity_access import (
    derive_access_edges,
    grants_from_mappings,
)
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.shared.enums import RelationshipType
from domain.shared.errors import GraphIntegrityViolation
from domain.resources.models import NormalizedResource
from domain.shared.identifiers import ResourceId, TenantId


#: Resource types whose policies grant access. An identity is never its
#: own access target, and pairing two identities would assert a
#: relationship IAM does not express this way.
_IDENTITY_TYPES = frozenset({"iam_role", "iam_user"})


class BuildResourceGraph:
    """Builds a tenant-scoped ``ResourceGraph`` from normalized resources."""

    def build(
        self, *, tenant_id: TenantId, resources: Iterable[NormalizedResource]
    ) -> ResourceGraph:
        result = self.build_with_report(tenant_id=tenant_id, resources=resources)
        return result.graph

    def build_with_report(
        self, *, tenant_id: TenantId, resources: Iterable[NormalizedResource]
    ) -> "GraphBuildResult":
        """Build the graph and report what happened while building it.

        ``build()`` is preserved as the original one-value signature so
        no existing caller changes; this variant additionally returns the
        edges that could not be added and the external nodes that were
        materialized.

        Two behaviours here fix a defect that made the previous phase's
        IAM role collector fatal (audit E1).
        """

        resources = list(resources)
        graph = ResourceGraph(tenant_id=tenant_id)
        collected: set[ResourceId] = set()

        for resource in resources:
            graph.add_node(
                GraphNode(
                    resource_id=resource.resource_id,
                    tenant_id=resource.tenant_id,
                    resource_type=resource.resource_type,
                    provider=resource.cloud_provider,
                    account_id=resource.account_id,
                    region=resource.region,
                    source_collector=resource.resource_type,
                    kind="collected",
                )
            )
            collected.add(resource.resource_id)

        # --- Materialize EXTERNAL targets.
        #
        # A collector may legitimately assert an edge to something that
        # is not a collectible resource: the internet, an AWS service
        # principal, a foreign account. Before this, such an edge hit
        # add_edge's referential-integrity check and raised, aborting the
        # WHOLE graph and therefore the whole scan — so an IAM role with
        # any trust relationship killed the scan.
        #
        # The alternative (dropping those edges) would lose exactly the
        # signal that makes cross-resource rules possible: "this role is
        # assumable from the internet" IS the finding.
        external_targets = {
            relationship.target_resource_id
            for resource in resources
            for relationship in resource.relationships
            if relationship.target_resource_id not in collected
        }
        for target in sorted(external_targets, key=str):
            graph.add_node(
                GraphNode(
                    resource_id=target,
                    tenant_id=tenant_id,
                    resource_type=_external_type(target),
                    name=str(target),
                    kind="external",
                    # We did not enumerate it; we only know something
                    # pointed at it. Rules can tell the difference.
                    confidence="medium",
                    source_collector="relationship-inference",
                )
            )

        # --- Add edges, isolating per-edge failure.
        #
        # One malformed relationship must not cost the entire graph, for
        # the same reason one inaccessible resource must not cost an
        # entire scan. Rejected edges are reported, never silently
        # swallowed: a graph missing an edge it should have is a
        # cross-resource rule that silently stops firing.
        rejected: list[tuple[ResourceId, ResourceId, str]] = []
        seen: set[tuple] = set()

        for resource in resources:
            for relationship in resource.relationships:
                # The collector's own evidence, when it supplied any,
                # is merged OVER the generic provenance — a collector
                # that knows exactly why it asserted an edge should not
                # have that knowledge overwritten by a default.
                edge = GraphEdge(
                    source_id=resource.resource_id,
                    target_id=relationship.target_resource_id,
                    relationship_type=relationship.relationship_type,
                    source_collector=resource.resource_type,
                    evidence={
                        "asserted_by": str(resource.resource_id),
                        "resource_type": resource.resource_type,
                        **dict(relationship.evidence),
                    },
                    confidence=relationship.confidence or "high",
                )
                # Two collectors observing the same relationship assert
                # one edge, not two.
                if edge.identity in seen:
                    continue
                try:
                    graph.add_edge(edge)
                except GraphIntegrityViolation as exc:
                    rejected.append(
                        (resource.resource_id, relationship.target_resource_id, str(exc))
                    )
                    continue
                seen.add(edge.identity)

        # --- Computed relationships (STEP 2).
        #
        # Everything above materializes relationships a COLLECTOR
        # asserted. This derives edges the collectors did not assert but
        # the evidence supports: identity -> resource access, matched
        # from IAM policy grants against the resources actually
        # collected.
        #
        # The distinction matters and is documented in
        # docs/architecture/resource-graph.md: a collected relationship
        # is something AWS told us; a computed one is something we
        # concluded. They carry different source_collector values so a
        # reader can always tell which is which.
        rejected.extend(self._derive_identity_access(graph, resources, seen))

        return GraphBuildResult(
            graph=graph,
            external_nodes=tuple(sorted(external_targets, key=str)),
            rejected_edges=tuple(rejected),
        )

    @staticmethod
    def _derive_identity_access(
        graph: ResourceGraph,
        resources: list[NormalizedResource],
        seen: set[tuple],
    ) -> list[tuple[ResourceId, ResourceId, str]]:
        """``ACCESSES`` edges from identities to the resources they name.

        ``ACCESSES`` is reused rather than a new type invented: "this
        principal can reach this resource" is exactly what it already
        means where CloudTrail asserts it, and it is already classified
        traversable.

        Only resources OTHER than the identity itself are candidates, and
        an unconstrained grant contributes no edges at all — see
        ``domain/graph/identity_access.py`` for why a wildcard must not
        become one edge per resource.
        """

        rejected: list[tuple[ResourceId, ResourceId, str]] = []
        candidates = [
            r.resource_id for r in resources if r.resource_type not in _IDENTITY_TYPES
        ]
        if not candidates:
            return rejected

        for resource in resources:
            if resource.resource_type not in _IDENTITY_TYPES:
                continue
            grants = grants_from_mappings(resource.attributes.get("access_grants"))
            if not grants:
                continue

            for access in derive_access_edges(grants, candidates):
                edge = GraphEdge(
                    source_id=resource.resource_id,
                    target_id=access.target,
                    relationship_type=RelationshipType.ACCESSES,
                    source_collector="identity-access-derivation",
                    confidence=access.confidence,
                    evidence={
                        "derived": True,
                        "evidence_level": access.evidence,
                        "matched_pattern": access.matched_pattern,
                        "matched_actions": list(access.matched_actions),
                        "conditioned": access.conditioned,
                        "source_arn": str(resource.resource_id),
                        "resource_arn": str(access.target),
                    },
                )
                if edge.identity in seen:
                    continue
                seen.add(edge.identity)
                try:
                    graph.add_edge(edge)
                except GraphIntegrityViolation as exc:
                    rejected.append((resource.resource_id, access.target, str(exc)))
        return rejected


def _external_type(target: ResourceId) -> str:
    """Classify an external target from its identifier prefix.

    The prefixes are the ones collectors actually emit. An unrecognized
    target becomes ``external_resource`` rather than being guessed at.
    """

    value = str(target)
    if value == "internet":
        return "internet"
    if value.startswith("aws-account:"):
        return "aws_account"
    if value.startswith("aws-service:"):
        return "aws_service"
    if value.startswith("azure-tenant:"):
        return "azure_tenant"
    return "external_resource"


@dataclass(frozen=True, slots=True)
class GraphBuildResult:
    """The graph plus what happened while building it."""

    graph: ResourceGraph
    #: Targets materialized because nothing collected them.
    external_nodes: tuple[ResourceId, ...] = ()
    #: ``(source, target, reason)`` for every edge that could not be
    #: added. Non-empty means the graph is incomplete and cross-resource
    #: rules over it may under-report.
    rejected_edges: tuple[tuple[ResourceId, ResourceId, str], ...] = ()

    @property
    def is_complete(self) -> bool:
        return not self.rejected_edges
