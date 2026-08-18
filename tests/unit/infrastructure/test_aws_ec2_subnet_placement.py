"""STEP 8A.1 — locating the workload in the network topology.

STEP 8A built the network: VPC, subnet, route table, internet gateway,
NACL. What it could not answer was the question every one of those
resources exists to serve — *which subnet is this instance in?* The
graph had a topology and a set of workloads with no edge between them.

The gap was narrower than earlier audits in this repository claimed.
``SubnetId`` has been collected since Phase 3 and stored as an
attribute; those audits stated it was not collected at all, which was
wrong (corrected in ``docs/audits/aws-network-completion.md`` §2). What
was genuinely missing was the *edge*. An attribute holding the string
``"subnet-aaaa1111"`` is not a graph relationship: no rule can traverse
it, no validator can tell whether the subnet was ever collected, and no
report can say the instance sits behind a permissive NACL.

Three properties are asserted here and each is a way the change could
have been made wrongly:

**The subnet comes from AWS, or not at all.** Only
``DescribeInstances.Reservations[].Instances[].SubnetId``. Never derived
from the VPC id, an IP address, a tag, an ARN or a Terraform file — the
tests below feed instances carrying every one of those misleading
signals and require no edge when the field itself is absent.

**Adding an edge must not add attack surface.** ``ATTACHED_TO`` is
classified informational, so the new edge is not traversable. An
attacker does not travel *into* a subnet, and a topology edge that
silently became a path step would manufacture attack paths out of
ordinary network layout.

**The old edges still mean what they meant.** The instance already
emitted ``ATTACHED_TO`` per security group. Adding a second
``ATTACHED_TO`` with a different kind of target is only safe because
every rule traversing it filters on ``target_type``; the coexistence is
asserted exactly rather than assumed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from application.graph.build_resource_graph import BuildResourceGraph
from domain.attack_paths.classification import is_traversable
from domain.graph.validation import Severity, graph_fingerprint, validate_graph
from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.normalizers.ec2 import normalize_ec2_instance
from infrastructure.cloud.aws.normalizers.network import (
    normalize_internet_gateway,
    normalize_network_acl,
    normalize_route_table,
    normalize_subnet,
    normalize_vpc,
)

TENANT = TenantId("acme")
ACCOUNT = "111111111111"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REGION = "us-east-1"

VPC = "vpc-0a1b2c3d"
SUBNET = "subnet-aaaa1111"
OTHER_SUBNET = "subnet-bbbb2222"
IGW = "igw-0f1e2d3c"
RTB = "rtb-01234567"
ACL = "acl-0abcdef0"
INSTANCE = "i-0123456789abcdef0"

#: The exact AWS field the edge is allowed to come from. Asserted as
#: evidence so a future refactor cannot quietly re-source it.
SUBNET_SOURCE_FIELD = "DescribeInstances.Reservations[].Instances[].SubnetId"


def ec2(
    *,
    instance_id: str = INSTANCE,
    subnet_id: str | None = SUBNET,
    vpc_id: str | None = VPC,
    security_group_ids: tuple[str, ...] = (),
    tags: dict[str, str] | None = None,
    public_ip: str | None = None,
):
    return normalize_ec2_instance(
        instance_id=instance_id,
        state="running",
        region=REGION,
        vpc_id=vpc_id,
        subnet_id=subnet_id,
        security_group_ids=security_group_ids,
        public_ip=public_ip,
        tags=tags or {},
        tenant_id=TENANT,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


def subnet_edges(resource):
    """Only the edges pointing at something that is a subnet here."""

    return tuple(
        r
        for r in resource.relationships
        if str(r.target_resource_id).startswith("subnet-")
    )


# ---------------------------------------------------------------------
# 1. EC2 with a SubnetId
# ---------------------------------------------------------------------


class TestInstanceWithSubnetId:
    def test_an_attached_to_edge_points_at_the_subnet(self) -> None:
        resource = ec2()
        edges = subnet_edges(resource)
        assert len(edges) == 1
        assert edges[0].target_resource_id == ResourceId(SUBNET)
        assert edges[0].relationship_type is RelationshipType.ATTACHED_TO

    def test_the_edge_names_the_aws_field_it_came_from(self) -> None:
        edge = subnet_edges(ec2())[0]
        assert edge.evidence["source_field"] == SUBNET_SOURCE_FIELD

    def test_confidence_is_high_because_aws_stated_it(self) -> None:
        # Both endpoints and the link between them came from one
        # DescribeInstances response. Nothing is inferred, so anything
        # below "high" would understate what we actually know.
        assert subnet_edges(ec2())[0].confidence == "high"

    def test_the_attribute_is_kept_as_well_as_the_edge(self) -> None:
        # The attribute predates the edge and other code reads it. The
        # edge is additive; replacing the attribute would be a silent
        # breaking change for anything already consuming it.
        resource = ec2()
        assert resource.attributes["subnet_id"] == SUBNET

    def test_exactly_one_edge_even_though_vpc_id_is_also_present(self) -> None:
        # A VPC edge from this side would duplicate the VPC's own
        # CONTAINS edge in the opposite direction, giving "is this in
        # that VPC" two answers that can drift.
        resource = ec2(vpc_id=VPC)
        assert len(resource.relationships) == 1


# ---------------------------------------------------------------------
# 2. EC2 without a SubnetId — the anti-inference cases
# ---------------------------------------------------------------------


class TestInstanceWithoutSubnetId:
    def test_no_subnet_id_produces_no_edge(self) -> None:
        assert ec2(subnet_id=None).relationships == ()

    def test_an_empty_string_subnet_id_produces_no_edge(self) -> None:
        # AWS does not return "", but a normalizer upstream could pass
        # one through. An empty ResourceId is not a resource.
        assert ec2(subnet_id="").relationships == ()

    def test_the_subnet_is_not_inferred_from_the_vpc_id(self) -> None:
        resource = ec2(subnet_id=None, vpc_id=VPC)
        assert subnet_edges(resource) == ()

    def test_the_subnet_is_not_inferred_from_a_tag(self) -> None:
        resource = ec2(
            subnet_id=None,
            tags={"Subnet": SUBNET, "subnet_id": SUBNET, "Name": "web-in-subnet-aaaa1111"},
        )
        assert subnet_edges(resource) == ()

    def test_the_subnet_is_not_inferred_from_an_ip_address(self) -> None:
        resource = ec2(subnet_id=None, public_ip="203.0.113.5")
        assert subnet_edges(resource) == ()

    def test_security_group_edges_are_unaffected_by_a_missing_subnet(self) -> None:
        resource = ec2(subnet_id=None, security_group_ids=("sg-1", "sg-2"))
        assert len(resource.relationships) == 2
        assert {str(r.target_resource_id) for r in resource.relationships} == {
            "sg-1",
            "sg-2",
        }


# ---------------------------------------------------------------------
# 3. Coexistence with the security-group edges
# ---------------------------------------------------------------------


class TestSubnetAndSecurityGroupEdgesCoexist:
    """The case the pre-existing collector tests no longer cover.

    Those tests asserted over *all* relationships as a stand-in for "the
    security group relationships", which held only while the instance
    had nothing else to emit. They are now scoped to their subject and
    this class owns the combined shape.
    """

    def test_the_full_edge_set_is_exactly_the_groups_plus_the_subnet(self) -> None:
        resource = ec2(security_group_ids=("sg-1", "sg-2"))
        assert {
            (str(r.target_resource_id), r.relationship_type)
            for r in resource.relationships
        } == {
            ("sg-1", RelationshipType.ATTACHED_TO),
            ("sg-2", RelationshipType.ATTACHED_TO),
            (SUBNET, RelationshipType.ATTACHED_TO),
        }

    def test_only_the_subnet_edge_carries_the_subnet_source_field(self) -> None:
        # The two kinds of ATTACHED_TO are told apart downstream by the
        # target node's type, but their provenance differs too, and a
        # security group edge acquiring subnet provenance would mean the
        # normalizer had confused them.
        resource = ec2(security_group_ids=("sg-1",))
        with_field = [
            r
            for r in resource.relationships
            if r.evidence.get("source_field") == SUBNET_SOURCE_FIELD
        ]
        assert len(with_field) == 1
        assert with_field[0].target_resource_id == ResourceId(SUBNET)

    def test_the_subnet_edge_is_ordered_after_the_security_groups(self) -> None:
        # Not cosmetic: `graph_fingerprint` sorts, but NormalizedResource
        # equality does not, and the conformance suite compares resources
        # directly. A stable order keeps two scans of unchanged
        # infrastructure comparing equal.
        resource = ec2(security_group_ids=("sg-1", "sg-2"))
        assert [str(r.target_resource_id) for r in resource.relationships] == [
            "sg-1",
            "sg-2",
            SUBNET,
        ]


# ---------------------------------------------------------------------
# 4. Subnet -> route table (STEP 8A, verified rather than re-implemented)
# ---------------------------------------------------------------------


def route_table(*, associations, routes=None):
    return normalize_route_table(
        route_table={
            "RouteTableId": RTB,
            "VpcId": VPC,
            "Routes": routes if routes is not None else [],
            "Associations": associations,
        },
        region=REGION,
        tenant_id=TENANT,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


class TestSubnetToRouteTableAssociation:
    def test_the_association_comes_from_the_aws_association_record(self) -> None:
        resource = route_table(
            associations=[
                {
                    "RouteTableAssociationId": "rtbassoc-1",
                    "SubnetId": SUBNET,
                    "AssociationState": {"State": "associated"},
                }
            ]
        )
        edges = subnet_edges(resource)
        assert len(edges) == 1
        assert edges[0].target_resource_id == ResourceId(SUBNET)
        assert edges[0].relationship_type is RelationshipType.ATTACHED_TO
        assert (
            edges[0].evidence["source_field"]
            == "DescribeRouteTables.RouteTables[].Associations[].SubnetId"
        )

    def test_the_subnet_does_not_emit_the_inverse_edge(self) -> None:
        # One fact, one edge. A subnet asserting its own route table
        # would let the two directions disagree after a partial scan.
        resource = normalize_subnet(
            subnet={"SubnetId": SUBNET, "VpcId": VPC, "CidrBlock": "10.0.1.0/24"},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
            account_id=ACCOUNT,
        )
        assert resource.relationships == ()

    def test_a_main_association_with_no_subnet_produces_no_edge(self) -> None:
        # The main route table governs every subnet with no explicit
        # association, but AWS does not enumerate them. Emitting edges to
        # subnets we were never told about would be inference.
        resource = route_table(
            associations=[
                {
                    "RouteTableAssociationId": "rtbassoc-main",
                    "Main": True,
                    "AssociationState": {"State": "associated"},
                }
            ]
        )
        assert subnet_edges(resource) == ()
        assert resource.attributes["is_main"] is True

    def test_a_gateway_association_produces_no_subnet_edge(self) -> None:
        resource = route_table(
            associations=[
                {"RouteTableAssociationId": "rtbassoc-gw", "GatewayId": IGW}
            ]
        )
        assert subnet_edges(resource) == ()

    def test_a_malformed_association_is_skipped_without_failing_the_rest(self) -> None:
        # A missing SubnetId, an explicit null and an empty object are
        # all "no subnet named here". None of them may abort the other
        # associations — one bad record must not cost the whole table.
        resource = route_table(
            associations=[
                {},
                {"SubnetId": None},
                {"RouteTableAssociationId": "rtbassoc-2", "SubnetId": ""},
                {"RouteTableAssociationId": "rtbassoc-3", "SubnetId": SUBNET},
            ]
        )
        assert [str(r.target_resource_id) for r in subnet_edges(resource)] == [SUBNET]
        # The malformed records survive as evidence rather than being
        # dropped: "we saw four associations, one named a subnet".
        assert len(resource.attributes["associations"]) == 4

    def test_duplicate_associations_to_one_subnet_produce_one_edge(self) -> None:
        resource = route_table(
            associations=[
                {"RouteTableAssociationId": "rtbassoc-1", "SubnetId": SUBNET},
                {"RouteTableAssociationId": "rtbassoc-2", "SubnetId": SUBNET},
            ]
        )
        assert len(subnet_edges(resource)) == 1

    def test_associations_are_emitted_in_sorted_order(self) -> None:
        resource = route_table(
            associations=[
                {"RouteTableAssociationId": "rtbassoc-2", "SubnetId": OTHER_SUBNET},
                {"RouteTableAssociationId": "rtbassoc-1", "SubnetId": SUBNET},
            ]
        )
        assert [str(r.target_resource_id) for r in subnet_edges(resource)] == sorted(
            [SUBNET, OTHER_SUBNET]
        )


# ---------------------------------------------------------------------
# 5. The whole topology, assembled
# ---------------------------------------------------------------------


def topology(*, instance_subnet_id: str | None = SUBNET, collect_subnet: bool = True):
    """VPC -> subnet -> {EC2, route table, NACL}; route table -> IGW.

    Every network resource STEP 8A collects is present, so an external
    node in this graph means something is genuinely unenumerated rather
    than merely outside the fixture. ``sg-1`` is the deliberate
    exception: security groups come from their own collector, and
    keeping one uncollected proves the instance's two ``ATTACHED_TO``
    edges are handled independently.
    """

    resources = [
        normalize_vpc(
            vpc={"VpcId": VPC, "CidrBlock": "10.0.0.0/16"},
            subnet_ids=[SUBNET] if collect_subnet else [],
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
            account_id=ACCOUNT,
        ),
        route_table(
            associations=[
                {"RouteTableAssociationId": "rtbassoc-1", "SubnetId": SUBNET}
            ],
            routes=[{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW}],
        ),
        normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "VpcId": VPC,
                "Entries": [],
                "Associations": [{"SubnetId": SUBNET}],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
            account_id=ACCOUNT,
        ),
        normalize_internet_gateway(
            gateway={
                "InternetGatewayId": IGW,
                "Attachments": [{"VpcId": VPC, "State": "available"}],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
            account_id=ACCOUNT,
        ),
        ec2(subnet_id=instance_subnet_id, security_group_ids=("sg-1",)),
    ]
    if collect_subnet:
        resources.append(
            normalize_subnet(
                subnet={
                    "SubnetId": SUBNET,
                    "VpcId": VPC,
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": True,
                },
                region=REGION,
                tenant_id=TENANT,
                collected_at=NOW,
                account_id=ACCOUNT,
            )
        )
    return resources


def build(resources):
    return BuildResourceGraph().build_with_report(tenant_id=TENANT, resources=resources)


class TestTopologyGraphIntegration:
    def test_the_instance_is_connected_to_the_collected_subnet(self) -> None:
        graph = build(topology()).graph
        edges = [
            e
            for e in graph.edges
            if str(e.source_id) == INSTANCE and str(e.target_id) == SUBNET
        ]
        assert len(edges) == 1
        assert edges[0].relationship_type is RelationshipType.ATTACHED_TO

    def test_the_topology_has_no_dangling_edges_and_no_errors(self) -> None:
        report = validate_graph(build(topology()).graph)
        assert report.errors == ()
        assert not [i for i in report.issues if i.code == "dangling_edge"]
        assert not [i for i in report.issues if i.code == "duplicate_edge"]
        assert not [i for i in report.issues if i.code == "self_loop"]

    def test_no_edge_is_rejected_and_the_subnet_is_not_external(self) -> None:
        result = build(topology())
        assert result.rejected_edges == ()
        assert result.is_complete
        # `sg-1` only, and by construction — every network resource is
        # collected here, so the subnet appearing in this tuple would
        # mean the placement edge had lost its target.
        assert result.external_nodes == (ResourceId("sg-1"),)

    def test_every_edge_target_is_a_node_in_the_graph(self) -> None:
        graph = build(topology()).graph
        node_ids = {n.resource_id for n in graph.nodes}
        assert {e.target_id for e in graph.edges} <= node_ids
        assert {e.source_id for e in graph.edges} <= node_ids

    def test_the_expected_topology_edges_are_all_present(self) -> None:
        graph = build(topology()).graph
        actual = {
            (str(e.source_id), str(e.target_id), e.relationship_type)
            for e in graph.edges
        }
        assert actual == {
            (VPC, SUBNET, RelationshipType.CONTAINS),
            (RTB, SUBNET, RelationshipType.ATTACHED_TO),
            (RTB, IGW, RelationshipType.CONNECTS_TO),
            (ACL, SUBNET, RelationshipType.PROTECTS),
            (IGW, VPC, RelationshipType.ATTACHED_TO),
            (INSTANCE, SUBNET, RelationshipType.ATTACHED_TO),
            (INSTANCE, "sg-1", RelationshipType.ATTACHED_TO),
        }

    def test_the_instance_and_the_subnet_agree_on_tenant_and_account(self) -> None:
        graph = build(topology()).graph
        nodes = {str(n.resource_id): n for n in graph.nodes}
        assert nodes[INSTANCE].tenant_id == nodes[SUBNET].tenant_id == TENANT
        assert nodes[INSTANCE].account_id == nodes[SUBNET].account_id == ACCOUNT
        report = validate_graph(graph)
        assert not [i for i in report.issues if i.code == "cross_account_edge"]

    def test_the_new_edge_is_not_traversable(self) -> None:
        # The load-bearing assertion of STEP 8A.1. If this ever passes as
        # True, ordinary network layout starts generating attack paths:
        # every instance in a public subnet would appear to be one step
        # from everything else in it.
        graph = build(topology()).graph
        edge = next(
            e
            for e in graph.edges
            if str(e.source_id) == INSTANCE and str(e.target_id) == SUBNET
        )
        assert is_traversable(edge) is False

    def test_no_edge_in_the_network_topology_is_traversable(self) -> None:
        graph = build(topology()).graph
        network_ids = {VPC, SUBNET, RTB, ACL, INSTANCE}
        assert not [
            e
            for e in graph.edges
            if str(e.source_id) in network_ids
            and str(e.target_id) in network_ids
            and is_traversable(e)
        ]


class TestMissingTargetSubnet:
    """The instance names a subnet the scan never collected.

    Real cause: a scan scoped to EC2 only, a subnet in another region, or
    a permission denied on DescribeSubnets. The edge must survive as a
    statement about what AWS said, marked as unenumerated — dropping it
    would lose the fact, and silently promoting the target to a collected
    node would claim we saw something we did not.
    """

    def test_the_edge_is_kept_and_the_target_is_marked_external(self) -> None:
        result = build(topology(collect_subnet=False))
        graph = result.graph
        assert ResourceId(SUBNET) in result.external_nodes
        node = next(n for n in graph.nodes if str(n.resource_id) == SUBNET)
        assert node.is_external
        assert node.source_collector == "relationship-inference"

    def test_the_edge_is_not_rejected(self) -> None:
        result = build(topology(collect_subnet=False))
        assert not [r for r in result.rejected_edges if str(r[1]) == SUBNET]

    def test_an_uncollected_subnet_is_never_reported_as_collected(self) -> None:
        graph = build(topology(collect_subnet=False)).graph
        node = next(n for n in graph.nodes if str(n.resource_id) == SUBNET)
        # `external_resource`, not `aws_subnet`: the id prefix is not
        # evidence of a type, and a rule targeting aws_subnet must not
        # match a node nobody enumerated.
        assert node.resource_type == "external_resource"
        assert node.confidence == "medium"

    def test_the_missing_subnet_produces_no_validation_error(self) -> None:
        # A not-fully-enumerated graph is normal, not corrupt.
        report = validate_graph(build(topology(collect_subnet=False)).graph)
        assert report.errors == ()
        assert not [
            i for i in report.issues if i.code == "orphan_external_node"
        ]

    def test_an_instance_in_a_different_subnet_does_not_attach_to_this_one(self) -> None:
        graph = build(topology(instance_subnet_id=OTHER_SUBNET)).graph
        assert not [
            e
            for e in graph.edges
            if str(e.source_id) == INSTANCE and str(e.target_id) == SUBNET
        ]


class TestTopologyDeterminism:
    def test_the_fingerprint_is_stable_across_identical_input(self) -> None:
        assert graph_fingerprint(build(topology()).graph) == graph_fingerprint(
            build(topology()).graph
        )

    def test_the_fingerprint_ignores_collector_ordering(self) -> None:
        forward = topology()
        assert graph_fingerprint(build(forward).graph) == graph_fingerprint(
            build(list(reversed(forward))).graph
        )

    def test_the_fingerprint_changes_when_the_instance_moves_subnet(self) -> None:
        # The counterpart to the two tests above: a fingerprint that
        # ignored ordering by ignoring the edge would pass them both.
        assert graph_fingerprint(build(topology()).graph) != graph_fingerprint(
            build(topology(instance_subnet_id=OTHER_SUBNET)).graph
        )

    def test_the_fingerprint_changes_when_the_placement_is_lost(self) -> None:
        assert graph_fingerprint(build(topology()).graph) != graph_fingerprint(
            build(topology(instance_subnet_id=None)).graph
        )

    def test_validation_counts_are_stable(self) -> None:
        first = validate_graph(build(topology()).graph)
        second = validate_graph(build(topology()).graph)
        assert first.relationship_counts == second.relationship_counts
        assert (first.node_count, first.edge_count) == (
            second.node_count,
            second.edge_count,
        )
        assert all(i.severity is not Severity.ERROR for i in first.issues)
