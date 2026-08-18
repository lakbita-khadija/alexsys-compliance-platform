"""STEP 1 integration — the workload → identity link reaches the graph.

`test_aws_instance_profile_resolution.py` proves the collector emits the
relationship. This proves it survives graph construction and is visible
to the query layer — the seam that three separate defects in this
repository have lived in.

**Scope boundary.** This step deliberately stops at `EC2 → IAM Role`. The
`IAM Role → S3` half belongs to STEP 2, and a test asserting the complete
flagship chain here would pass only by fabricating the second edge. What
is asserted instead is that the graph is now *capable* of representing
the previously missing middle link.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from application.graph.build_resource_graph import BuildResourceGraph
from domain.graph.queries import edges_of, find_paths, related_nodes
from domain.graph.validation import graph_fingerprint, validate_graph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ACCOUNT = "111111111111"

INSTANCE = ResourceId("i-web")
ROLE = ResourceId(f"arn:aws:iam::{ACCOUNT}:role/app-server-role")
BUCKET = ResourceId("bucket-data")


def resource(rid, rtype, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=rid,
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


@pytest.fixture
def estate():
    """The smallest realistic estate: EC2 → (instance profile) → IAM role."""

    workload = resource(
        INSTANCE,
        "ec2_instance",
        {
            "public_ip": "203.0.113.10",
            "instance_profile_arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/AppServerProfile",
            "instance_profile_role_arn": str(ROLE),
            "instance_profile_resolution": "resolved",
        },
        (
            ResourceRelationship(
                target_resource_id=ROLE,
                relationship_type=RelationshipType.ASSUMES,
                evidence={
                    "instance_profile_arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/AppServerProfile",
                    "resolved_instance_profile": "AppServerProfile",
                    "resolved_role_arn": str(ROLE),
                    "resolved_via": "iam:GetInstanceProfile",
                },
                confidence="high",
            ),
        ),
    )
    role = resource(ROLE, "iam_role", {"has_administrator_access": True})
    return [workload, role]


def build(estate):
    return BuildResourceGraph().build(tenant_id=TENANT, resources=estate)


class TestTheLinkReachesTheGraph:
    def test_both_nodes_exist(self, estate) -> None:
        graph = build(estate)
        assert graph.has_node(INSTANCE)
        assert graph.has_node(ROLE)
        # The role is a COLLECTED node, not an external one. Before
        # IamRoleCollector was registered this would have been external —
        # "points outside the scan" rather than "we enumerated it".
        assert graph.get_node(ROLE).is_external is False

    def test_the_identity_edge_exists(self, estate) -> None:
        graph = build(estate)
        edges = edges_of(graph, INSTANCE, relationship_type=RelationshipType.ASSUMES)
        assert len(edges) == 1
        assert edges[0].target_id == ROLE

    def test_the_edge_carries_the_collector_evidence(self, estate) -> None:
        graph = build(estate)
        edge = edges_of(graph, INSTANCE, relationship_type=RelationshipType.ASSUMES)[0]

        # Provenance survived BuildResourceGraph rather than being
        # replaced by the generic default.
        assert edge.evidence["resolved_via"] == "iam:GetInstanceProfile"
        assert edge.evidence["resolved_role_arn"] == str(ROLE)
        assert edge.evidence["resolved_instance_profile"] == "AppServerProfile"
        # Generic provenance is still present alongside it.
        assert edge.evidence["asserted_by"] == str(INSTANCE)
        assert edge.confidence == "high"

    def test_the_graph_validates(self, estate) -> None:
        report = validate_graph(build(estate))
        errors = [i for i in report.issues if i.severity == "error"]
        assert errors == []

    def test_the_fingerprint_is_deterministic(self, estate) -> None:
        assert graph_fingerprint(build(estate)) == graph_fingerprint(build(estate))

    def test_input_order_does_not_change_the_fingerprint(self, estate) -> None:
        assert graph_fingerprint(build(estate)) == graph_fingerprint(
            build(list(reversed(estate)))
        )

    def test_the_relationship_is_visible_to_graph_queries(self, estate) -> None:
        graph = build(estate)
        neighbours = related_nodes(
            graph, INSTANCE, relationship_type=RelationshipType.ASSUMES
        )
        assert [str(n.resource_id) for n in neighbours] == [str(ROLE)]


class TestTraversal:
    def test_the_middle_link_is_now_traversable(self, estate) -> None:
        """The regression this step exists to create.

        `ASSUMES` is classified traversable, so `find_paths` can now walk
        workload → identity. Before this step the edge did not exist and
        this returned nothing.
        """

        paths = find_paths(build(estate), source=INSTANCE, target=ROLE)
        assert len(paths) == 1
        assert paths[0][0].relationship_type is RelationshipType.ASSUMES

    def test_the_second_half_of_the_flagship_chain_is_still_absent(self, estate) -> None:
        """Scope guard for STEP 2.

        Add a sensitive bucket and assert there is STILL no path from the
        workload to it. No collector emits identity → resource, so
        claiming that reach would be fabrication. When STEP 2 lands, this
        test is replaced by its positive counterpart — not deleted
        quietly.
        """

        with_bucket = estate + [resource(BUCKET, "s3_bucket", {"public": False})]
        assert find_paths(build(with_bucket), source=INSTANCE, target=BUCKET) == ()


class TestNoEdgeWithoutEvidence:
    def test_an_unresolved_profile_produces_no_identity_edge(self) -> None:
        # The shape the collector emits when GetInstanceProfile was
        # denied: the attribute records UNKNOWN, and NO relationship.
        workload = resource(
            INSTANCE,
            "ec2_instance",
            {"instance_profile_arn": "arn:aws:iam::111111111111:instance-profile/P",
             "instance_profile_resolution": "denied"},
        )
        graph = build([workload])
        assert edges_of(graph, INSTANCE, relationship_type=RelationshipType.ASSUMES) == ()


class TestAttackPathReadiness:
    """Proof the graph can now represent the missing middle link.

    Deliberately NOT an assertion that the flagship attack path fires —
    that needs STEP 2's identity → resource edge, and asserting it here
    would require inventing one.
    """

    def test_the_analyzer_runs_over_the_new_edge_without_inventing_a_path(
        self, estate
    ) -> None:
        from application.attack_paths.analyze_attack_paths import AnalyzeAttackPaths

        graph = build(estate)
        paths = AnalyzeAttackPaths().analyze(
            tenant_id=TENANT, graph=graph, findings=(), resources=estate
        )

        # The instance has a public IP but no open security group, and
        # the role has no PUBLICLY_EXPOSED edge — so no scenario is
        # evidenced. The new edge must not, on its own, manufacture one.
        assert paths == ()

    def test_severity_vocabulary_is_untouched(self) -> None:
        # Guards against this step quietly widening an enum.
        assert [s.value for s in Severity] == ["critical", "high", "medium", "low"]
