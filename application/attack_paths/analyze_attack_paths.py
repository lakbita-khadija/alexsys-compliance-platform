"""``AnalyzeAttackPaths`` (blueprint §4) — composite risk discovery.

Answers a question no single rule can: *given everything we collected,
can an attacker get from outside to something that matters?* A rule sees
one resource. This sees the chain.

## What changed, and what did not

This class was a documented placeholder returning ``()``. It is now
implemented, in place — there is no second analyzer. Its signature is
unchanged except for one additive optional parameter (``resources``),
because graph nodes carry identity and provenance but not attributes,
and "is this bucket public" lives in the attributes.

``ScanCloudAccount`` already called this method and already routed its
result into ``ScanResult.attack_paths``, so implementing it lights up the
whole pipeline without touching the pipeline.

## The governing constraint: only what the graph evidences

Four scenarios ship. Each one is grounded in edges and attributes that
collectors genuinely produce today (see the current-state audit §2).
Deliberately absent is the textbook chain *internet → workload → IAM role
→ data*: no collector emits a workload-to-identity edge, so building that
path would mean inventing the relationship. A fabricated attack path is
worse than a missing one — it sends a security team to investigate
something that does not exist, and it does so with a confident severity
attached.

## False-positive control

The single most consequential decision is that **connectivity is not
reachability**. ``ATTACHED_TO`` and ``ALLOWS`` are not traversable: an
attacker does not travel *into* a security group. Treating every edge as
a step is precisely how a graph becomes a false-positive generator.
Beyond that: blocked edges are excluded, ``UNKNOWN`` never reads as
``True``, external nodes cap confidence, undetermined evidence takes a
scoring penalty, traversal is depth-bounded and cycle-free, and a
malformed candidate is skipped rather than allowed to abort the scan.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from domain.attack_paths.classification import (
    ResourceRole,
    exposure_is_undetermined,
    is_data_bearing,
    is_sensitive,
    is_traversable,
    privilege_evidence,
    privilege_is_undetermined,
    public_exposure_evidence,
    role_of,
    unrestricted_ingress_evidence,
)
from domain.attack_paths.models import AttackPath
from domain.attack_paths.scoring import SCORING_MODEL_VERSION, score_path
from domain.findings.models import Finding
from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.graph.queries import edges_of, find_paths, internet_node_ids
from domain.resources.models import NormalizedResource
from domain.shared.enums import RelationshipType
from domain.shared.identifiers import AttackPathId, ResourceId, TenantId

#: Bumped when the discovery algorithm changes, independently of the
#: scoring model — a path can be rediscovered the same way and scored
#: differently, or vice versa, and conflating the two versions would make
#: historical comparison meaningless.
ALGORITHM_VERSION = "apa-1.0"

#: Hops an attacker is assumed willing to chain. Four covers every chain
#: the current vocabulary can express and bounds the combinatorial cost —
#: an unbounded search over a large tenant's graph is a denial of service
#: against our own scanner.
MAX_DEPTH = 4

SCENARIO_PUBLIC_IDENTITY = "public_identity_with_privilege"
SCENARIO_EXPOSED_DATA = "internet_to_sensitive_data"
SCENARIO_EXPOSED_WORKLOAD = "internet_to_exposed_workload"
SCENARIO_DATA_FLOW_TO_EXPOSED_STORE = "sensitive_data_flow_to_exposed_store"
#: The flagship chain (STEP 3). Every hop is evidenced: exposure from the
#: workload's own attributes plus an open network control, workload ->
#: identity from `iam:GetInstanceProfile`, identity -> data from matched
#: IAM policy grants.
SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY = "internet_to_workload_to_identity_to_data"

_CONFIDENCE_ORDER = ("high", "medium", "low", "unknown")


def _weakest(confidences: Iterable[str]) -> str:
    """Weakest-link confidence.

    A chain is exactly as trustworthy as its least trustworthy link.
    Averaging would let two confident edges launder one guess.
    """

    worst = 0
    for confidence in confidences:
        try:
            worst = max(worst, _CONFIDENCE_ORDER.index(confidence))
        except ValueError:
            worst = len(_CONFIDENCE_ORDER) - 1  # unrecognized reads as unknown
    return _CONFIDENCE_ORDER[worst]


def _chain(nodes: Sequence[GraphNode]) -> str:
    """A readable ``a -> b -> c`` rendering for the evidence."""

    return " -> ".join(str(node.resource_id) for node in nodes)


class AnalyzeAttackPaths:
    """Discovers composite attack paths in a tenant-scoped graph."""

    def analyze(
        self,
        *,
        tenant_id: TenantId,
        graph: ResourceGraph,
        findings: Sequence[Finding],
        resources: Sequence[NormalizedResource] = (),
    ) -> tuple[AttackPath, ...]:
        """Every attack path the graph evidences, deterministically ordered.

        ``resources`` is optional so every existing caller keeps working.
        Without it the two attribute-driven scenarios simply find nothing
        — a smaller result, never a wrong one.
        """

        attributes = {r.resource_id: dict(r.attributes) for r in resources}
        findings_by_resource: dict[ResourceId, list[Finding]] = {}
        for finding in findings:
            findings_by_resource.setdefault(finding.resource_id, []).append(finding)

        paths: list[AttackPath] = []
        for build in (
            self._public_identities,
            self._exposed_sensitive_data,
            self._exposed_workloads,
            self._data_flows_into_exposed_stores,
            self._internet_to_data_via_identity,
        ):
            for candidate in build(graph, attributes):
                try:
                    paths.append(
                        self._to_attack_path(
                            tenant_id=tenant_id,
                            findings_by_resource=findings_by_resource,
                            **candidate,
                        )
                    )
                except Exception:
                    # One malformed candidate must never abort a scan
                    # (§12). The aggregate's own invariants are the
                    # authority on what is constructible; a candidate
                    # that violates one is dropped, and the other paths
                    # — and the rest of the scan — survive.
                    continue

        # Highest risk first, then id: a stable order the UI can page and
        # two runs can diff.
        return tuple(sorted(paths, key=lambda p: (-p.risk_score, str(p.id))))

    # -----------------------------------------------------------------
    # Scenario builders. Each yields plain dicts so _to_attack_path owns
    # scoring and construction in exactly one place.
    # -----------------------------------------------------------------

    def _public_identities(self, graph: ResourceGraph, attributes: dict) -> list[dict]:
        """Internet → an identity anyone can assume.

        The best-evidenced scenario in the current graph: the IAM role
        collector emits a real ``PUBLICLY_EXPOSED`` edge from a role whose
        trust policy admits a wildcard principal, and the same collector
        reports whether that role carries administrator access.
        """

        candidates = []
        for internet in internet_node_ids(graph):
            for edge in edges_of(
                graph,
                internet,
                direction="incoming",
                relationship_type=RelationshipType.PUBLICLY_EXPOSED,
            ):
                if edge.blocked or not graph.has_node(edge.source_id):
                    continue
                identity = graph.get_node(edge.source_id)
                if role_of(identity) is not ResourceRole.IDENTITY:
                    continue
                attrs = attributes.get(identity.resource_id, {})
                candidates.append(
                    {
                        "scenario": SCENARIO_PUBLIC_IDENTITY,
                        "nodes": (graph.get_node(internet), identity),
                        "edges": (edge,),
                        "has_internet_edge": True,
                        "exposure_attributes": public_exposure_evidence(attrs),
                        "unrestricted_ingress": False,
                        "privilege_attributes": privilege_evidence(attrs),
                        "evidence_incomplete": privilege_is_undetermined(attrs),
                        "why": (
                            "this identity's trust policy admits a principal "
                            "outside the account, so it can be assumed from the internet"
                        ),
                    }
                )
        return candidates

    def _exposed_sensitive_data(self, graph: ResourceGraph, attributes: dict) -> list[dict]:
        """A sensitive store readable from the internet.

        Driven by the resource's OWN attributes, never by a neighbour's.
        No collector emits an internet edge for storage, but the S3 and
        Azure storage collectors do read public-access state directly.
        """

        candidates = []
        for node in graph.nodes:
            # Data-bearing only. An identity is a valuable target but it
            # does not STORE anything, and it already has a scenario of
            # its own that words the risk correctly.
            if node.is_external or not is_data_bearing(node):
                continue
            attrs = attributes.get(node.resource_id)
            if attrs is None:
                continue
            exposure = public_exposure_evidence(attrs)
            if not exposure:
                continue
            candidates.append(
                {
                    "scenario": SCENARIO_EXPOSED_DATA,
                    "nodes": (node,),
                    "edges": (),
                    "has_internet_edge": False,
                    "exposure_attributes": exposure,
                    "unrestricted_ingress": False,
                    "privilege_attributes": privilege_evidence(attrs),
                    "evidence_incomplete": exposure_is_undetermined(attrs),
                    "why": "this resource holds sensitive data and is readable from the internet",
                }
            )
        return candidates

    def _exposed_workloads(self, graph: ResourceGraph, attributes: dict) -> list[dict]:
        """Internet → a workload, through a network control that admits it.

        Both halves are required. A public IP behind a closed security
        group is not reachable, and an open security group protecting
        nothing public is not an entry point. Reporting either alone is
        the classic CSPM false positive.

        ``ATTACHED_TO`` appears here as a **reachability witness**, not as
        a traversal step — it names which group is at fault. It remains
        non-traversable everywhere else.
        """

        candidates = []
        for node in graph.nodes:
            if node.is_external or role_of(node) is not ResourceRole.WORKLOAD:
                continue
            attrs = attributes.get(node.resource_id)
            if attrs is None:
                continue
            public_address = attrs.get("public_ip")
            if not public_address or public_address is True:
                continue

            for edge in edges_of(
                graph, node.resource_id, relationship_type=RelationshipType.ATTACHED_TO
            ):
                if edge.blocked or not graph.has_node(edge.target_id):
                    continue
                control = graph.get_node(edge.target_id)
                if role_of(control) is not ResourceRole.NETWORK_CONTROL:
                    continue
                control_attrs = attributes.get(control.resource_id, {})
                ingress = unrestricted_ingress_evidence(control_attrs)
                if not ingress:
                    continue
                candidates.append(
                    {
                        "scenario": SCENARIO_EXPOSED_WORKLOAD,
                        "nodes": (control, node),
                        "edges": (edge,),
                        "has_internet_edge": False,
                        "exposure_attributes": ("public_ip",) + ingress,
                        "unrestricted_ingress": True,
                        "privilege_attributes": (),
                        "evidence_incomplete": exposure_is_undetermined(control_attrs),
                        "why": (
                            "this workload has a public address and an attached network "
                            "control that admits unrestricted ingress"
                        ),
                    }
                )
        return candidates

    def _data_flows_into_exposed_stores(
        self, graph: ResourceGraph, attributes: dict
    ) -> list[dict]:
        """Something writes into a store that the internet can read.

        The genuinely composite scenario, and the one that uses bounded
        traversal: CloudTrail delivering audit logs to a public bucket is
        not a fact about either resource alone.

        Uses the existing ``find_paths`` (depth-bounded, cycle-free,
        blocked-aware) and then discards any path routed through a
        non-traversable edge, so configuration edges can never become
        movement.
        """

        candidates = []
        exposed_stores = [
            node
            for node in graph.nodes
            if not node.is_external
            and is_data_bearing(node)
            and public_exposure_evidence(attributes.get(node.resource_id, {}))
        ]

        for store in exposed_stores:
            for source in graph.nodes:
                if source.resource_id == store.resource_id or source.is_external:
                    continue
                for path in find_paths(
                    graph,
                    source=source.resource_id,
                    target=store.resource_id,
                    max_depth=MAX_DEPTH,
                ):
                    if not all(is_traversable(edge) for edge in path):
                        continue
                    nodes = self._nodes_along(graph, source.resource_id, path)
                    if nodes is None:
                        continue
                    store_attrs = attributes.get(store.resource_id, {})
                    candidates.append(
                        {
                            "scenario": SCENARIO_DATA_FLOW_TO_EXPOSED_STORE,
                            "nodes": nodes,
                            "edges": path,
                            "has_internet_edge": False,
                            "exposure_attributes": public_exposure_evidence(store_attrs),
                            "unrestricted_ingress": False,
                            "privilege_attributes": (),
                            "evidence_incomplete": exposure_is_undetermined(store_attrs),
                            "why": (
                                "this resource writes into a store that is readable "
                                "from the internet"
                            ),
                        }
                    )
        return candidates

    def _internet_to_data_via_identity(
        self, graph: ResourceGraph, attributes: dict
    ) -> list[dict]:
        """Internet → workload → identity → sensitive data.

        The chain a CSPM exists to find, and the one that was
        unevidenced until STEP 1 and STEP 2 supplied its two missing
        edges. Every hop is now grounded:

        1. **Internet → workload** — the workload's own public address
           AND an attached network control admitting unrestricted
           ingress. Both halves required, as in scenario 3.
        2. **Workload → identity** — an `ASSUMES` edge resolved from
           `iam:GetInstanceProfile`, never from a name convention.
        3. **Identity → data** — an `ACCESSES` edge derived from an IAM
           policy grant that *names* the resource. An unconstrained
           wildcard grant produces no edge, so this hop cannot appear
           because a role can reach everything.

        Reported only when the target is data-bearing. Reaching another
        workload or a network control is not the objective.
        """

        candidates = []
        for workload in graph.nodes:
            if workload.is_external or role_of(workload) is not ResourceRole.WORKLOAD:
                continue
            exposure = self._internet_exposure_of(graph, workload, attributes)
            if exposure is None:
                continue
            control, ingress = exposure

            for target in graph.nodes:
                if target.is_external or not is_data_bearing(target):
                    continue
                for path in find_paths(
                    graph,
                    source=workload.resource_id,
                    target=target.resource_id,
                    max_depth=MAX_DEPTH,
                ):
                    if not self._is_identity_chain(graph, path):
                        continue
                    nodes = self._nodes_along(graph, workload.resource_id, path)
                    if nodes is None:
                        continue
                    identity = next(
                        (n for n in nodes if role_of(n) is ResourceRole.IDENTITY), None
                    )
                    identity_attrs = (
                        attributes.get(identity.resource_id, {}) if identity else {}
                    )
                    candidates.append(
                        {
                            "scenario": SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY,
                            # The network control leads the chain so the
                            # narrative reads internet -> ... -> data.
                            "nodes": (control,) + nodes,
                            "edges": path,
                            "has_internet_edge": False,
                            "exposure_attributes": ("public_ip",) + ingress,
                            "unrestricted_ingress": True,
                            "privilege_attributes": privilege_evidence(identity_attrs),
                            "evidence_incomplete": (
                                privilege_is_undetermined(identity_attrs)
                                or exposure_is_undetermined(
                                    attributes.get(control.resource_id, {})
                                )
                            ),
                            "why": (
                                "this workload is reachable from the internet, can assume "
                                "an identity, and that identity is granted access to a "
                                "resource holding sensitive data"
                            ),
                        }
                    )
        return candidates

    @staticmethod
    def _internet_exposure_of(
        graph: ResourceGraph, workload: GraphNode, attributes: dict
    ) -> tuple[GraphNode, tuple[str, ...]] | None:
        """``(network control, ingress evidence)`` if internet-reachable.

        Shares scenario 3's definition of exposure rather than inventing
        a second one — two definitions of "public" would eventually
        disagree, and a path is only as trustworthy as its entry point.
        """

        attrs = attributes.get(workload.resource_id)
        if attrs is None:
            return None
        public_address = attrs.get("public_ip")
        if not public_address or public_address is True:
            return None

        for edge in edges_of(
            graph, workload.resource_id, relationship_type=RelationshipType.ATTACHED_TO
        ):
            if edge.blocked or not graph.has_node(edge.target_id):
                continue
            control = graph.get_node(edge.target_id)
            if role_of(control) is not ResourceRole.NETWORK_CONTROL:
                continue
            ingress = unrestricted_ingress_evidence(
                attributes.get(control.resource_id, {})
            )
            if ingress:
                return control, ingress
        return None

    @staticmethod
    def _is_identity_chain(graph: ResourceGraph, path: Sequence[GraphEdge]) -> bool:
        """Whether a path goes through an identity, not merely to data.

        Requires at least one `ASSUMES` followed by an `ACCESSES`, and
        every edge traversable. Without this, a direct workload->data
        edge would be reported under the identity scenario and the
        narrative would name a privilege hop that never happened.
        """

        if len(path) < 2:
            return False
        if not all(is_traversable(edge) for edge in path):
            return False
        kinds = [edge.relationship_type for edge in path]
        try:
            assumes_at = kinds.index(RelationshipType.ASSUMES)
        except ValueError:
            return False
        return RelationshipType.ACCESSES in kinds[assumes_at + 1 :]

    @staticmethod
    def _nodes_along(
        graph: ResourceGraph, start: ResourceId, edges: Sequence[GraphEdge]
    ) -> tuple[GraphNode, ...] | None:
        """Node chain for an edge chain, or ``None`` if any node is gone.

        Returning ``None`` rather than raising keeps a stale reference
        from aborting the sweep — the caller simply skips the candidate.
        """

        ids = [start] + [edge.target_id for edge in edges]
        if not all(graph.has_node(i) for i in ids):
            return None
        return tuple(graph.get_node(i) for i in ids)

    # -----------------------------------------------------------------

    def _to_attack_path(
        self,
        *,
        tenant_id: TenantId,
        findings_by_resource: dict[ResourceId, list[Finding]],
        scenario: str,
        nodes: tuple[GraphNode, ...],
        edges: tuple[GraphEdge, ...],
        has_internet_edge: bool,
        exposure_attributes: tuple[str, ...],
        unrestricted_ingress: bool,
        privilege_attributes: tuple[str, ...],
        evidence_incomplete: bool,
        why: str,
    ) -> AttackPath:
        target = nodes[-1]
        blocked = any(edge.blocked for edge in edges)
        confidence = _weakest(
            [n.confidence for n in nodes] + [e.confidence for e in edges]
        )

        breakdown = score_path(
            has_internet_edge=has_internet_edge,
            exposure_attributes=exposure_attributes,
            unrestricted_ingress=unrestricted_ingress,
            privilege_attributes=privilege_attributes,
            target_sensitivity=role_of(target).value if is_sensitive(target) else None,
            relationship_types=tuple(e.relationship_type.value for e in edges),
            hop_count=len(edges),
            confidence=confidence,
            evidence_incomplete=evidence_incomplete,
            blocked=blocked,
        )

        # Deterministic composite identity: the same path in two scans of
        # unchanged infrastructure gets the same id, so it can be tracked
        # over time. No uuid4, no clock.
        path_id = AttackPathId(
            f"{tenant_id!s}:{scenario}:{nodes[0].resource_id!s}:{target.resource_id!s}"
        )

        contributing = tuple(
            sorted(
                {
                    f.id
                    for node in nodes
                    for f in findings_by_resource.get(node.resource_id, [])
                    if f.status.value == "fail"
                },
                key=str,
            )
        )

        return AttackPath(
            id=path_id,
            tenant_id=tenant_id,
            nodes=nodes,
            edges=edges,
            contributing_finding_ids=contributing,
            attack_techniques=(),
            severity=breakdown.severity,
            risk_score=breakdown.value,
            algorithm_version=ALGORITHM_VERSION,
            scenario=scenario,
            confidence=confidence,
            evidence={
                "chain": _chain(nodes),
                "entry_point": str(nodes[0].resource_id),
                "target": str(target.resource_id),
                "target_role": role_of(target).value,
                "why_risky": why,
                "exposure_evidence": list(exposure_attributes),
                "privilege_evidence": list(privilege_attributes),
                "relationships": [e.relationship_type.value for e in edges],
                "confidence": confidence,
                "evidence_incomplete": evidence_incomplete,
                "scoring_model": SCORING_MODEL_VERSION,
                "score_factors": list(breakdown.explain()),
            },
        )


__all__ = [
    "ALGORITHM_VERSION",
    "MAX_DEPTH",
    "SCENARIO_DATA_FLOW_TO_EXPOSED_STORE",
    "SCENARIO_EXPOSED_DATA",
    "SCENARIO_EXPOSED_WORKLOAD",
    "SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY",
    "SCENARIO_PUBLIC_IDENTITY",
    "AnalyzeAttackPaths",
]
