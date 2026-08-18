"""STEP 8A — network topology as graph nodes and edges (§10).

Scope is deliberately narrow: prove the five new resource types become
valid graph nodes and that their edges survive validation. **No attack
path scenario is added here** (§11), and these tests assert that
explicitly — the analyzer must behave exactly as it did before, because
network data alone does not yet make any new chain honest.

What is worth checking, given the graph's own invariants:

* a referenced-but-uncollected VPC becomes an `external` node rather
  than a dangling-edge error, and a future rule must not read that as
  "the VPC does not exist";
* the fingerprint stays deterministic, since routes and ACL entries are
  ordered collections that could easily reorder between scans;
* `CONTAINS` and `PROTECTS` stay **informational** — this step adds
  topology, not new attack surface.
"""

from __future__ import annotations

from datetime import datetime, timezone

from application.attack_paths.analyze_attack_paths import AnalyzeAttackPaths
from application.graph.build_resource_graph import BuildResourceGraph
from domain.attack_paths.classification import is_traversable
from domain.graph.validation import graph_fingerprint, validate_graph
from domain.shared.enums import RelationshipType, Severity
from domain.shared.identifiers import TenantId
from infrastructure.cloud.aws.normalizers.network import (
    normalize_internet_gateway,
    normalize_network_acl,
    normalize_route_table,
    normalize_subnet,
    normalize_vpc,
)

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REGION = "us-east-1"
ACCOUNT = "111111111111"

VPC = "vpc-0a1b2c3d"
SUBNET = "subnet-aaaa1111"
IGW = "igw-0f1e2d3c"
RTB = "rtb-01234567"
ACL = "acl-0abcdef0"


def _kw():
    return dict(region=REGION, tenant_id=TENANT, collected_at=NOW, account_id=ACCOUNT)


def estate(*, include_vpc=True, include_igw=True):
    """A small but complete public-subnet topology."""

    resources = []
    if include_vpc:
        resources.append(normalize_vpc(vpc={"VpcId": VPC}, subnet_ids=[SUBNET], **_kw()))
    resources.append(
        normalize_subnet(
            subnet={
                "SubnetId": SUBNET,
                "VpcId": VPC,
                "CidrBlock": "10.0.1.0/24",
                "MapPublicIpOnLaunch": True,
            },
            **_kw(),
        )
    )
    resources.append(
        normalize_route_table(
            route_table={
                "RouteTableId": RTB,
                "VpcId": VPC,
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW}],
                "Associations": [{"RouteTableAssociationId": "a-1", "SubnetId": SUBNET}],
            },
            **_kw(),
        )
    )
    if include_igw:
        resources.append(
            normalize_internet_gateway(
                gateway={
                    "InternetGatewayId": IGW,
                    "Attachments": [{"VpcId": VPC, "State": "available"}],
                },
                **_kw(),
            )
        )
    resources.append(
        normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "VpcId": VPC,
                "Associations": [{"NetworkAclAssociationId": "b-1", "SubnetId": SUBNET}],
                "Entries": [
                    {
                        "RuleNumber": 100,
                        "RuleAction": "allow",
                        "Egress": False,
                        "CidrBlock": "0.0.0.0/0",
                        "Protocol": "-1",
                    }
                ],
            },
            **_kw(),
        )
    )
    return resources


def build(resources):
    return BuildResourceGraph().build(tenant_id=TENANT, resources=resources)


class TestNodesAreCreated:
    def test_every_resource_becomes_a_node(self) -> None:
        graph = build(estate())
        assert {n.resource_type for n in graph.nodes} == {
            "aws_vpc",
            "aws_subnet",
            "aws_route_table",
            "aws_internet_gateway",
            "aws_network_acl",
        }

    def test_nodes_are_collected_not_external(self) -> None:
        graph = build(estate())
        assert {n.kind for n in graph.nodes} == {"collected"}

    def test_tenant_and_account_are_consistent(self) -> None:
        graph = build(estate())
        assert {str(n.tenant_id) for n in graph.nodes} == {"acme"}
        assert {n.account_id for n in graph.nodes} == {ACCOUNT}


class TestEdgesAreValid:
    def test_the_expected_edges_exist(self) -> None:
        graph = build(estate())
        edges = {
            (str(e.source_id), str(e.target_id), e.relationship_type)
            for e in graph.edges
        }
        assert (VPC, SUBNET, RelationshipType.CONTAINS) in edges
        assert (RTB, IGW, RelationshipType.CONNECTS_TO) in edges
        assert (IGW, VPC, RelationshipType.ATTACHED_TO) in edges
        assert (ACL, SUBNET, RelationshipType.PROTECTS) in edges

    def test_no_dangling_edges(self) -> None:
        report = validate_graph(build(estate()))
        dangling = [i for i in report.issues if i.code == "dangling_edge"]
        assert dangling == []

    def test_no_duplicate_edges(self) -> None:
        report = validate_graph(build(estate()))
        duplicates = [i for i in report.issues if i.code == "duplicate_edge"]
        assert duplicates == []

    def test_the_graph_has_no_errors(self) -> None:
        report = validate_graph(build(estate()))
        errors = [i for i in report.issues if i.severity is Severity.CRITICAL]
        assert errors == []

    def test_an_uncollected_vpc_becomes_external_not_an_error(self) -> None:
        """The partial-permission case, and the trap it sets.

        If the IGW is collected but its VPC is not, the edge target
        materializes as an `external` node with reduced confidence rather
        than failing referential integrity. That is correct — but it
        means a future rule must not read an external VPC node as "the
        VPC does not exist". Pinned here so the behaviour is a decision
        rather than a surprise.
        """

        graph = build(estate(include_vpc=False))
        vpc_node = next(n for n in graph.nodes if str(n.resource_id) == VPC)
        assert vpc_node.kind == "external"

        report = validate_graph(graph)
        assert [i for i in report.issues if i.code == "dangling_edge"] == []


class TestDeterminism:
    def test_the_fingerprint_is_stable(self) -> None:
        # Routes and ACL entries are ordered collections that could
        # easily reorder between scans; the fingerprint is what would
        # catch it.
        first = graph_fingerprint(build(estate()))
        second = graph_fingerprint(build(estate()))
        assert first == second

    def test_input_order_does_not_change_the_fingerprint(self) -> None:
        forward = graph_fingerprint(build(estate()))
        backward = graph_fingerprint(build(list(reversed(estate()))))
        assert forward == backward

    def test_edge_ordering_is_deterministic(self) -> None:
        runs = [
            [(str(e.source_id), str(e.target_id)) for e in build(estate()).edges]
            for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)


class TestTopologyIsNotTraversable:
    """§11 — this step adds topology, not new attack surface."""

    def test_contains_and_protects_stay_informational(self) -> None:
        graph = build(estate())
        for edge in graph.edges:
            if edge.relationship_type in (
                RelationshipType.CONTAINS,
                RelationshipType.PROTECTS,
                RelationshipType.ATTACHED_TO,
            ):
                assert not is_traversable(edge)

    def test_connects_to_is_traversable(self) -> None:
        # The one traversable edge added: a route to an internet gateway
        # is genuine network reachability, which is what CONNECTS_TO has
        # always meant.
        graph = build(estate())
        route_edges = [
            e for e in graph.edges if e.relationship_type is RelationshipType.CONNECTS_TO
        ]
        assert route_edges and all(is_traversable(e) for e in route_edges)


class TestNoNewAttackPathScenario:
    def test_network_topology_alone_produces_no_paths(self) -> None:
        """The §11 boundary, asserted rather than assumed.

        The estate is a genuinely public subnet — public-IP-on-launch, a
        default route to an attached internet gateway, an allow-all
        NACL. It still produces no attack path, because no workload is
        located in it: `ec2_instance` does not record its `SubnetId`, so
        the topology cannot be joined to anything worth reaching.
        """

        graph = build(estate())
        paths = AnalyzeAttackPaths().analyze(
            tenant_id=TENANT, graph=graph, findings=(), resources=estate()
        )
        assert paths == ()

    def test_network_resources_are_never_attack_path_targets(self) -> None:
        from domain.attack_paths.classification import ResourceRole, role_of

        graph = build(estate())
        for node in graph.nodes:
            assert role_of(node) is ResourceRole.OTHER
