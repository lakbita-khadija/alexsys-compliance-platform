"""STEP 8A — AWS network topology collectors and normalizers.

Two things carry the weight here, and neither is "the field is copied".

**Structure survives.** A route table must not collapse into
`has_internet_route: true`, and a NACL must not collapse into
`allow_all`. Derived booleans are added *alongside* the evidence, so a
rule that disagrees with our summary can look at what we actually saw. A
CSPM that cannot show its working cannot defend a finding.

**Nothing is inferred from an id.** `CONNECTS_TO` is emitted only for a
default route whose target genuinely starts with `igw-`. A NAT gateway,
a virtual private gateway and a VPC endpoint all look like "a gateway
id" and none of them provides inbound internet reachability — asserting
one does would fabricate an attack path.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError
from infrastructure.cloud.aws.normalizers.network import (
    normalize_internet_gateway,
    normalize_network_acl,
    normalize_route_table,
    normalize_subnet,
    normalize_vpc,
)
from infrastructure.cloud.aws.resource_collectors.network import (
    InternetGatewayCollector,
    NetworkAclCollector,
    RouteTableCollector,
    SubnetCollector,
    VpcCollector,
)

TENANT = TenantId("acme")
ACCOUNT = "111111111111"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REGION = "us-east-1"

VPC = "vpc-0a1b2c3d"
SUBNET_A = "subnet-aaaa1111"
SUBNET_B = "subnet-bbbb2222"
IGW = "igw-0f1e2d3c"
NAT = "nat-09876543"
RTB = "rtb-01234567"
ACL = "acl-0abcdef0"


# ---------------------------------------------------------------------
# Fakes — modelled on documented describe_* response shapes
# ---------------------------------------------------------------------


class FakeEc2Session:
    """Serves one `ec2` client whose paginators return canned pages."""

    def __init__(self, pages: dict, *, errors: dict | None = None) -> None:
        self._pages = pages
        self._errors = errors or {}
        self.region_name = REGION
        self.operations: list[str] = []

    def client(self, service_name: str):
        assert service_name == "ec2", f"unexpected client: {service_name}"
        outer = self

        class _Paginator:
            def __init__(self, operation: str) -> None:
                self._operation = operation

            def paginate(self):
                outer.operations.append(self._operation)
                if self._operation in outer._errors:
                    raise outer._errors[self._operation]
                return outer._pages.get(self._operation, [{}])

        class _Client:
            def get_paginator(self, operation: str):
                return _Paginator(operation)

        return _Client()


def denied(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, operation
    )


def throttled(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "Throttling", "Message": "rate exceeded"}}, operation
    )


def collect(collector_cls, pages, errors=None):
    session = FakeEc2Session(pages, errors=errors)
    collector = collector_cls(
        session=session, tenant_id=TENANT, clock=lambda: NOW, account_id=ACCOUNT
    )
    return collector.collect(), session


# ---------------------------------------------------------------------
# Shared behaviour across all five
# ---------------------------------------------------------------------

ALL = [
    (VpcCollector, "describe_vpcs", "Vpcs", {"VpcId": VPC, "CidrBlock": "10.0.0.0/16"}),
    (SubnetCollector, "describe_subnets", "Subnets", {"SubnetId": SUBNET_A, "VpcId": VPC}),
    (RouteTableCollector, "describe_route_tables", "RouteTables", {"RouteTableId": RTB}),
    (
        InternetGatewayCollector,
        "describe_internet_gateways",
        "InternetGateways",
        {"InternetGatewayId": IGW},
    ),
    (NetworkAclCollector, "describe_network_acls", "NetworkAcls", {"NetworkAclId": ACL}),
]


@pytest.mark.parametrize("collector_cls, operation, key, item", ALL)
class TestEveryCollectorSharesTheContract:
    def test_a_normal_response_is_collected(self, collector_cls, operation, key, item) -> None:
        resources, _ = collect(collector_cls, {operation: [{key: [item]}]})
        assert len(resources) == 1

    def test_an_empty_response_yields_nothing(self, collector_cls, operation, key, item) -> None:
        # Empty is a determinate answer, not an error.
        resources, _ = collect(collector_cls, {operation: [{key: []}]})
        assert resources == ()

    def test_a_missing_key_yields_nothing(self, collector_cls, operation, key, item) -> None:
        resources, _ = collect(collector_cls, {operation: [{}]})
        assert resources == ()

    def test_access_denied_raises_a_translated_error(
        self, collector_cls, operation, key, item
    ) -> None:
        # Never a raw botocore type: AwsCollector isolates per-collector
        # failures on this class.
        with pytest.raises(AwsCollectionError):
            collect(collector_cls, {}, errors={operation: denied(operation)})

    def test_throttling_raises_a_translated_error(
        self, collector_cls, operation, key, item
    ) -> None:
        with pytest.raises(AwsCollectionError):
            collect(collector_cls, {}, errors={operation: throttled(operation)})

    def test_tenant_and_account_propagate(self, collector_cls, operation, key, item) -> None:
        resources, _ = collect(collector_cls, {operation: [{key: [item]}]})
        assert resources[0].tenant_id == TENANT
        assert resources[0].account_id == ACCOUNT
        assert resources[0].cloud_provider is CloudProvider.AWS
        assert resources[0].region == REGION
        assert resources[0].collected_at == NOW

    def test_normalization_is_deterministic(self, collector_cls, operation, key, item) -> None:
        first, _ = collect(collector_cls, {operation: [{key: [item]}]})
        second, _ = collect(collector_cls, {operation: [{key: [item]}]})
        assert [r.attributes for r in first] == [r.attributes for r in second]
        assert [r.relationships for r in first] == [r.relationships for r in second]

    def test_pagination_is_followed(self, collector_cls, operation, key, item) -> None:
        # Two pages. A collector that read only the first would silently
        # under-report, which is the worst kind of collection defect.
        second = dict(item)
        id_field = next(k for k in item if k.endswith("Id"))
        second[id_field] = item[id_field] + "-page2"
        resources, _ = collect(
            collector_cls, {operation: [{key: [item]}, {key: [second]}]}
        )
        assert len(resources) == 2


# ---------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------


class TestVpc:
    def test_core_attributes(self) -> None:
        resource = normalize_vpc(
            vpc={
                "VpcId": VPC,
                "CidrBlock": "10.0.0.0/16",
                "State": "available",
                "IsDefault": True,
                "InstanceTenancy": "default",
                "Tags": [{"Key": "env", "Value": "prod"}],
            },
            subnet_ids=(),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.resource_type == "aws_vpc"
        assert resource.attributes["cidr_block"] == "10.0.0.0/16"
        assert resource.attributes["is_default"] is True
        assert resource.tags == {"env": "prod"}

    def test_every_associated_cidr_is_kept(self) -> None:
        # A VPC can carry several blocks; a rule reasoning about address
        # space needs all of them, not just the primary.
        resource = normalize_vpc(
            vpc={
                "VpcId": VPC,
                "CidrBlock": "10.0.0.0/16",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.1.0.0/16"},
                    {"CidrBlock": "10.0.0.0/16"},
                ],
            },
            subnet_ids=(),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["cidr_blocks"] == ["10.0.0.0/16", "10.1.0.0/16"]

    def test_contains_edges_point_container_to_contained(self) -> None:
        resource = normalize_vpc(
            vpc={"VpcId": VPC},
            subnet_ids=[SUBNET_B, SUBNET_A],
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert [str(r.target_resource_id) for r in resource.relationships] == [
            SUBNET_A,
            SUBNET_B,
        ]
        assert all(
            r.relationship_type is RelationshipType.CONTAINS for r in resource.relationships
        )

    def test_no_subnets_means_no_edges(self) -> None:
        # Absence means "not observed", never "this VPC has no subnets".
        resource = normalize_vpc(
            vpc={"VpcId": VPC},
            subnet_ids=(),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()

    def test_the_collector_fetches_subnets_for_containment(self) -> None:
        resources, session = collect(
            VpcCollector,
            {
                "describe_vpcs": [{"Vpcs": [{"VpcId": VPC}]}],
                "describe_subnets": [{"Subnets": [{"SubnetId": SUBNET_A, "VpcId": VPC}]}],
            },
        )
        assert "describe_subnets" in session.operations
        assert len(resources[0].relationships) == 1

    def test_denied_subnets_does_not_fail_the_vpc_collection(self) -> None:
        """A permissions gap degrades the edge, not the resource.

        The VPCs were collected and are worth reporting. What must not
        happen is a VPC reported as containing nothing when we simply
        were not allowed to look — hence no edges, and the usual
        "not observed" meaning.
        """

        resources, _ = collect(
            VpcCollector,
            {"describe_vpcs": [{"Vpcs": [{"VpcId": VPC}]}]},
            errors={"describe_subnets": denied("DescribeSubnets")},
        )
        assert len(resources) == 1
        assert resources[0].relationships == ()


# ---------------------------------------------------------------------
# Subnet
# ---------------------------------------------------------------------


class TestSubnet:
    def test_core_attributes(self) -> None:
        resource = normalize_subnet(
            subnet={
                "SubnetId": SUBNET_A,
                "VpcId": VPC,
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
                "State": "available",
                "MapPublicIpOnLaunch": True,
                "AvailableIpAddressCount": 250,
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.resource_type == "aws_subnet"
        assert resource.attributes["vpc_id"] == VPC
        assert resource.attributes["map_public_ip_on_launch"] is True
        assert resource.attributes["availability_zone"] == "us-east-1a"

    def test_it_emits_no_relationships(self) -> None:
        # The containment edge belongs to the VPC. Emitting it here too
        # would give "is this subnet in that VPC" two answers that can
        # drift apart.
        resource = normalize_subnet(
            subnet={"SubnetId": SUBNET_A, "VpcId": VPC},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()

    def test_map_public_ip_defaults_to_false_not_unknown(self) -> None:
        # AWS always returns this field; its absence in a fake means the
        # fixture is thin, not that the value is undetermined.
        resource = normalize_subnet(
            subnet={"SubnetId": SUBNET_A},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["map_public_ip_on_launch"] is False

    def test_ipv6_blocks_are_sorted(self) -> None:
        resource = normalize_subnet(
            subnet={
                "SubnetId": SUBNET_A,
                "Ipv6CidrBlockAssociationSet": [
                    {"Ipv6CidrBlock": "2001:db8:2::/64"},
                    {"Ipv6CidrBlock": "2001:db8:1::/64"},
                ],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["ipv6_cidr_blocks"] == [
            "2001:db8:1::/64",
            "2001:db8:2::/64",
        ]


# ---------------------------------------------------------------------
# Route table
# ---------------------------------------------------------------------


def route_table(routes=(), associations=()):
    return {
        "RouteTableId": RTB,
        "VpcId": VPC,
        "Routes": list(routes),
        "Associations": list(associations),
    }


class TestRouteTable:
    def test_routes_are_preserved_in_order(self) -> None:
        resource = normalize_route_table(
            route_table=route_table(
                routes=[
                    {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW},
                ]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        destinations = [r["destination"] for r in resource.attributes["routes"]]
        assert destinations == ["10.0.0.0/16", "0.0.0.0/0"]

    def test_the_target_type_is_kept_not_flattened(self) -> None:
        # "which kind of gateway" is the entire difference between
        # internet egress and a private VPN link.
        resource = normalize_route_table(
            route_table=route_table(
                routes=[{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT}]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        route = resource.attributes["routes"][0]
        assert route["target_type"] == "nat_gateway"
        assert route["target_id"] == NAT

    def test_a_real_internet_route_emits_connects_to(self) -> None:
        resource = normalize_route_table(
            route_table=route_table(
                routes=[{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW}]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert len(resource.relationships) == 1
        edge = resource.relationships[0]
        assert edge.relationship_type is RelationshipType.CONNECTS_TO
        assert str(edge.target_resource_id) == IGW
        assert resource.attributes["has_internet_route"] is True

    def test_a_nat_gateway_default_route_is_not_an_internet_route(self) -> None:
        """The guard that stops a fabricated exposure.

        A default route to a NAT gateway gives outbound-only egress and
        no inbound reachability. Treating it as internet exposure would
        manufacture a path into every private subnet in the estate.
        """

        resource = normalize_route_table(
            route_table=route_table(
                routes=[{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": NAT}]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()
        assert resource.attributes["has_internet_route"] is False

    @pytest.mark.parametrize(
        "gateway", ["vgw-01234567", "vpce-01234567", "local", "eigw-01234567"]
    )
    def test_only_igw_prefixed_gateways_count(self, gateway) -> None:
        resource = normalize_route_table(
            route_table=route_table(
                routes=[{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": gateway}]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()

    def test_a_non_default_route_to_an_igw_is_not_internet_egress(self) -> None:
        # Routing one prefix through an IGW is not "open to the world".
        resource = normalize_route_table(
            route_table=route_table(
                routes=[{"DestinationCidrBlock": "203.0.113.0/24", "GatewayId": IGW}]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()

    def test_associations_and_main_flag(self) -> None:
        resource = normalize_route_table(
            route_table=route_table(
                associations=[
                    {"RouteTableAssociationId": "rtbassoc-1", "SubnetId": SUBNET_A},
                    {"RouteTableAssociationId": "rtbassoc-2", "Main": True},
                ]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["is_main"] is True
        assert resource.attributes["associated_subnet_ids"] == [SUBNET_A]

    def test_a_malformed_route_does_not_crash(self) -> None:
        # An unrecognized shape is recorded with nulls rather than
        # aborting the scan over one row.
        resource = normalize_route_table(
            route_table=route_table(routes=[{}]),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        route = resource.attributes["routes"][0]
        assert route["destination"] is None
        assert route["target_type"] is None

    def test_duplicate_igw_routes_produce_one_edge(self) -> None:
        resource = normalize_route_table(
            route_table=route_table(
                routes=[
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW},
                    {"DestinationIpv6CidrBlock": "::/0", "GatewayId": IGW},
                ]
            ),
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert len(resource.relationships) == 1
        assert resource.relationships[0].evidence["destinations"] == ["0.0.0.0/0", "::/0"]


# ---------------------------------------------------------------------
# Internet gateway
# ---------------------------------------------------------------------


class TestInternetGateway:
    def test_an_available_attachment_emits_attached_to(self) -> None:
        resource = normalize_internet_gateway(
            gateway={
                "InternetGatewayId": IGW,
                "Attachments": [{"VpcId": VPC, "State": "available"}],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert len(resource.relationships) == 1
        assert resource.relationships[0].relationship_type is RelationshipType.ATTACHED_TO
        assert str(resource.relationships[0].target_resource_id) == VPC
        assert resource.attributes["is_attached"] is True

    def test_an_unattached_gateway_emits_nothing(self) -> None:
        resource = normalize_internet_gateway(
            gateway={"InternetGatewayId": IGW, "Attachments": []},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()
        assert resource.attributes["is_attached"] is False

    @pytest.mark.parametrize("state", ["attaching", "detaching", "detached"])
    def test_a_transient_attachment_is_not_connectivity(self, state) -> None:
        # An attachment mid-attach is not connectivity, and putting a
        # transient state into a security conclusion is how a scan
        # reports something that stops being true a second later.
        resource = normalize_internet_gateway(
            gateway={"InternetGatewayId": IGW, "Attachments": [{"VpcId": VPC, "State": state}]},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()
        # The evidence is still preserved, whatever the state.
        assert resource.attributes["attachments"] == [{"vpc_id": VPC, "state": state}]

    def test_a_malformed_attachment_does_not_crash(self) -> None:
        resource = normalize_internet_gateway(
            gateway={"InternetGatewayId": IGW, "Attachments": [{}]},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.relationships == ()


# ---------------------------------------------------------------------
# Network ACL
# ---------------------------------------------------------------------


def entry(number, action="allow", *, egress=False, cidr="0.0.0.0/0", protocol="-1"):
    return {
        "RuleNumber": number,
        "RuleAction": action,
        "Egress": egress,
        "CidrBlock": cidr,
        "Protocol": protocol,
    }


class TestNetworkAcl:
    def test_ingress_and_egress_are_separated(self) -> None:
        resource = normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "VpcId": VPC,
                "Entries": [entry(100), entry(100, egress=True)],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert len(resource.attributes["ingress_entries"]) == 1
        assert len(resource.attributes["egress_entries"]) == 1

    def test_entries_are_ordered_by_rule_number(self) -> None:
        """Order is load bearing.

        A NACL evaluates lowest rule number first and stops at the first
        match, so `DENY 100` before `ALLOW 200` means the opposite of the
        reverse. Sorting also makes output deterministic regardless of
        API ordering.
        """

        resource = normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "Entries": [entry(200, "allow"), entry(100, "deny"), entry(150, "allow")],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        numbers = [e["rule_number"] for e in resource.attributes["ingress_entries"]]
        assert numbers == [100, 150, 200]

    def test_a_deny_rule_is_recorded_as_deny(self) -> None:
        resource = normalize_network_acl(
            acl={"NetworkAclId": ACL, "Entries": [entry(100, "deny")]},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["ingress_entries"][0]["rule_action"] == "deny"
        assert resource.attributes["has_unrestricted_ingress_rule"] is False

    def test_mixed_rules_keep_both(self) -> None:
        resource = normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "Entries": [entry(100, "deny", cidr="10.0.0.0/8"), entry(200, "allow")],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        actions = [e["rule_action"] for e in resource.attributes["ingress_entries"]]
        assert actions == ["deny", "allow"]

    def test_the_derived_flag_sits_alongside_the_evidence(self) -> None:
        # Derived booleans never replace what we saw.
        resource = normalize_network_acl(
            acl={"NetworkAclId": ACL, "Entries": [entry(100, "allow")]},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["has_unrestricted_ingress_rule"] is True
        assert resource.attributes["ingress_entries"][0]["cidr_block"] == "0.0.0.0/0"

    def test_port_ranges_are_preserved(self) -> None:
        resource = normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "Entries": [
                    {
                        "RuleNumber": 100,
                        "RuleAction": "allow",
                        "Egress": False,
                        "CidrBlock": "0.0.0.0/0",
                        "Protocol": "6",
                        "PortRange": {"From": 22, "To": 22},
                    }
                ],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        record = resource.attributes["ingress_entries"][0]
        assert (record["port_from"], record["port_to"]) == (22, 22)
        assert record["protocol"] == "6"

    def test_associations_emit_protects(self) -> None:
        resource = normalize_network_acl(
            acl={
                "NetworkAclId": ACL,
                "Associations": [
                    {"NetworkAclAssociationId": "aclassoc-2", "SubnetId": SUBNET_B},
                    {"NetworkAclAssociationId": "aclassoc-1", "SubnetId": SUBNET_A},
                ],
            },
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert all(
            r.relationship_type is RelationshipType.PROTECTS for r in resource.relationships
        )
        assert [str(r.target_resource_id) for r in resource.relationships] == [
            SUBNET_A,
            SUBNET_B,
        ]

    def test_a_malformed_entry_sorts_last_and_survives(self) -> None:
        resource = normalize_network_acl(
            acl={"NetworkAclId": ACL, "Entries": [{"RuleAction": "allow"}, entry(100)]},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        numbers = [e["rule_number"] for e in resource.attributes["ingress_entries"]]
        assert numbers == [100, None]
