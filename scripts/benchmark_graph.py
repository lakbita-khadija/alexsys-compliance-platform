"""Graph scale benchmark (expansion §15).

Measures graph construction and relationship-rule evaluation at 100, 500
and 1000 resources — the sizes §15 names.

**What this is not.** It is not a claim about production performance. It
builds a synthetic estate in memory with no cloud API, no database and no
network, so it measures exactly one thing: whether the adjacency indexes
turned relationship evaluation from O(R x N x E) into something that
scales. That was the question, and it is the only question this answers.

The comparison is against a deliberately reconstructed linear scan, not
against a git checkout of the old code, so both paths run in the same
process on the same data in the same interpreter.

Run:  python scripts/benchmark_graph.py
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from application.graph.build_resource_graph import BuildResourceGraph
from domain.graph.models import ResourceGraph
from domain.graph.queries import edges_of, find_resources
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.conditions import evaluate_condition
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("benchmark")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

#: One instance per security group, plus a shared "hub" group every
#: instance also attaches to. The hub is the interesting part: it gives
#: one node a large in-degree, which is where a linear scan hurts most
#: and where an index helps most.
SIZES = (100, 500, 1000)


def build_estate(total: int) -> list[NormalizedResource]:
    """``total`` is the resource count, matching how §15 states the sizes.

    Half instances, half security groups, plus one shared hub — so a
    "1000-resource estate" really contains 1000 resources rather than
    1000 pairs.
    """

    n = (total - 1) // 2
    resources: list[NormalizedResource] = []

    def make(rid: str, rtype: str, attributes, relationships=()):
        return NormalizedResource(
            resource_id=ResourceId(rid),
            resource_type=rtype,
            cloud_provider=CloudProvider.AWS,
            tenant_id=TENANT,
            region="us-east-1",
            attributes=attributes,
            tags={},
            relationships=relationships,
            collected_at=NOW,
        )

    resources.append(make("sg-hub", "security_group", {"unrestricted_ingress": True}))

    for i in range(n):
        sg = f"sg-{i}"
        resources.append(
            make(sg, "security_group", {"unrestricted_ingress": i % 10 == 0})
        )
        resources.append(
            make(
                f"i-{i}",
                "ec2_instance",
                {"public_ip": "1.2.3.4"},
                (
                    ResourceRelationship(
                        target_resource_id=ResourceId(sg),
                        relationship_type=RelationshipType.ATTACHED_TO,
                    ),
                    ResourceRelationship(
                        target_resource_id=ResourceId("sg-hub"),
                        relationship_type=RelationshipType.ATTACHED_TO,
                    ),
                ),
            )
        )
    return resources


CONDITION = {
    "relationship": "attached_to",
    "direction": "outgoing",
    "target_type": "security_group",
    "where": {"field": "unrestricted_ingress", "operator": "is_true"},
}


def linear_scan_edges(graph: ResourceGraph, resource_id: ResourceId):
    """What ``edges_of`` replaced: a full pass over every edge.

    Kept here rather than in the library so the comparison is honest —
    this is the code that used to run, reproduced, not a strawman.
    """

    return tuple(e for e in graph.edges if e.source_id == resource_id)


def timed(fn, repeat: int = 3) -> float:
    """Best of ``repeat``, in milliseconds.

    Best-of rather than mean: this is measuring the code, and a mean
    folds in whatever else the machine was doing.
    """

    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best * 1000


def main() -> None:
    print(f"{'resources':>10} {'nodes':>7} {'edges':>7} "
          f"{'build ms':>10} {'indexed ms':>12} {'scan ms':>10} {'speedup':>9}")
    print("-" * 72)

    for total in SIZES:
        estate = build_estate(total)
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=estate)
        by_id = {r.resource_id: r for r in estate}
        instances = [r for r in estate if r.resource_type == "ec2_instance"]

        build_ms = timed(lambda e=estate: BuildResourceGraph().build(tenant_id=TENANT, resources=e))

        def indexed(g=graph, rs=instances, b=by_id):
            for r in rs:
                evaluate_condition(CONDITION, r, graph=g, resources_by_id=b)

        def scan(g=graph, rs=instances):
            for r in rs:
                linear_scan_edges(g, r.resource_id)

        indexed_ms = timed(indexed)
        scan_ms = timed(scan)

        # Sanity: the two paths must see the same edges, or the speedup
        # is measuring a shortcut rather than an optimization.
        for r in instances[:20]:
            assert {e.identity for e in edges_of(graph, r.resource_id)} == {
                e.identity for e in linear_scan_edges(graph, r.resource_id)
            }
        assert len(find_resources(graph, "ec2_instance")) == len(instances)

        print(
            f"{len(estate):>10} {len(graph.nodes):>7} {len(graph.edges):>7} "
            f"{build_ms:>10.1f} {indexed_ms:>12.1f} {scan_ms:>10.1f} "
            f"{scan_ms / indexed_ms:>8.1f}x"
        )

    print()
    print("indexed ms = full three-valued rule evaluation over every instance")
    print("scan ms    = edge lookup ONLY, no evaluation — the indexed column")
    print("             does strictly more work, so the speedup is understated")


if __name__ == "__main__":
    main()
