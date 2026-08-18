"""AWS network topology → ``NormalizedResource`` (STEP 8A).

VPC, subnet, route table, internet gateway and network ACL. Grouped in
one module because they are one subsystem, share one AWS client (`ec2`),
and their relationships only make sense together.

Two principles run through all five, and both are anti-fabrication:

**Structure is preserved, not collapsed.** A route table becomes its
ordered list of routes, not `has_internet_route: true`. A NACL becomes
its ordered entries, not `allow_all: true`. Derived booleans are added
*alongside* the evidence, never instead of it — a rule that disagrees
with our summary must be able to look at what we actually saw. Collapsing
first is how a CSPM ends up unable to explain its own finding.

**Relationships come from AWS fields that name a resource, never from
inference.** `route_table --CONNECTS_TO--> igw` is emitted only when a
route's `GatewayId` literally starts with `igw-`; a `vgw-`, `nat-` or
`vpce-` target is a different kind of gateway and asserting internet
egress from it would be a fabricated path. See
`docs/audits/aws-network-foundation-current-state.md` §3 for the full
mapping of each edge onto the existing closed vocabulary — no new
`RelationshipType` was needed, which is what that vocabulary was
designed for.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId

#: The destination that means "everything not otherwise routed".
DEFAULT_ROUTES = frozenset({"0.0.0.0/0", "::/0"})

#: An internet gateway id prefix. `vgw-` (virtual private gateway),
#: `nat-` (NAT gateway) and `vpce-` (VPC endpoint) deliberately do NOT
#: qualify: none of them provides inbound reachability from the internet.
_IGW_PREFIX = "igw-"


def _tags(raw: Sequence[Mapping[str, str]] | None) -> dict[str, str]:
    return {tag["Key"]: tag["Value"] for tag in (raw or []) if "Key" in tag}


def _resource(
    *,
    resource_id: str,
    resource_type: str,
    region: str | None,
    attributes: dict[str, Any],
    tags: dict[str, str],
    relationships: tuple[ResourceRelationship, ...],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes=attributes,
        tags=tags,
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------


def normalize_vpc(
    *,
    vpc: Mapping[str, Any],
    subnet_ids: Sequence[str],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One VPC, plus ``CONTAINS`` edges to the subnets it holds.

    ``subnet_ids`` is supplied by the caller rather than read from the
    VPC response, because ``DescribeVpcs`` does not list subnets — the
    membership fact lives on the subnet. The edge is emitted here anyway
    so ``CONTAINS`` keeps its plain-English direction (container →
    contained); see the audit §3.6 for why that was preferred over
    inventing a `BELONGS_TO` type.

    An empty ``subnet_ids`` produces no edges. Absence means "not
    observed" — never "this VPC has no subnets".
    """

    cidr_blocks = tuple(
        sorted(
            association["CidrBlock"]
            for association in vpc.get("CidrBlockAssociationSet", [])
            if association.get("CidrBlock")
        )
    )

    attributes: dict[str, Any] = {
        "cidr_block": vpc.get("CidrBlock"),
        # Every associated block, not just the primary: a VPC can carry
        # several, and a rule reasoning about address space needs all.
        "cidr_blocks": list(cidr_blocks) or ([vpc["CidrBlock"]] if vpc.get("CidrBlock") else []),
        "state": vpc.get("State"),
        "is_default": bool(vpc.get("IsDefault", False)),
        "instance_tenancy": vpc.get("InstanceTenancy"),
        "dhcp_options_id": vpc.get("DhcpOptionsId"),
    }

    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(subnet_id),
            relationship_type=RelationshipType.CONTAINS,
            evidence={"source_field": "DescribeSubnets.Subnets[].VpcId"},
            confidence="high",
        )
        # Sorted so two scans of unchanged infrastructure produce an
        # identical edge order, which `graph_fingerprint` depends on.
        for subnet_id in sorted(set(subnet_ids))
    )

    return _resource(
        resource_id=vpc["VpcId"],
        resource_type="aws_vpc",
        region=region,
        attributes=attributes,
        tags=_tags(vpc.get("Tags")),
        relationships=relationships,
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Subnet
# ---------------------------------------------------------------------


def normalize_subnet(
    *,
    subnet: Mapping[str, Any],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One subnet. Emits **no** relationships.

    Its ``VpcId`` is recorded as an attribute, and the containment edge
    is emitted by the VPC (audit §3.6). Emitting an edge here as well
    would duplicate the same fact in two directions and produce a graph
    where "is this subnet in that VPC" has two answers that can drift.
    """

    ipv6_cidrs = tuple(
        sorted(
            association["Ipv6CidrBlock"]
            for association in subnet.get("Ipv6CidrBlockAssociationSet", [])
            if association.get("Ipv6CidrBlock")
        )
    )

    attributes: dict[str, Any] = {
        "vpc_id": subnet.get("VpcId"),
        "cidr_block": subnet.get("CidrBlock"),
        "ipv6_cidr_blocks": list(ipv6_cidrs),
        "availability_zone": subnet.get("AvailabilityZone"),
        "availability_zone_id": subnet.get("AvailabilityZoneId"),
        "state": subnet.get("State"),
        # The subnet-level half of "will an instance here be reachable".
        # NOT sufficient on its own: a public IP without a route to an
        # internet gateway reaches nothing. The route table supplies the
        # other half.
        "map_public_ip_on_launch": bool(subnet.get("MapPublicIpOnLaunch", False)),
        "assign_ipv6_address_on_creation": bool(
            subnet.get("AssignIpv6AddressOnCreation", False)
        ),
        "available_ip_address_count": subnet.get("AvailableIpAddressCount"),
        "is_default_for_az": bool(subnet.get("DefaultForAz", False)),
    }

    return _resource(
        resource_id=subnet["SubnetId"],
        resource_type="aws_subnet",
        region=region,
        attributes=attributes,
        tags=_tags(subnet.get("Tags")),
        relationships=(),
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Route table
# ---------------------------------------------------------------------


def _normalize_route(route: Mapping[str, Any]) -> dict[str, Any]:
    """One route, with its target kept as (type, id) rather than flattened.

    A route names exactly one target among a dozen mutually exclusive
    fields (`GatewayId`, `NatGatewayId`, `TransitGatewayId`, …). Reducing
    them to a single string would lose which kind it was, and "which kind
    of gateway" is the entire difference between internet egress and a
    private VPN link.
    """

    target_fields = (
        ("gateway", "GatewayId"),
        ("nat_gateway", "NatGatewayId"),
        ("transit_gateway", "TransitGatewayId"),
        ("vpc_peering_connection", "VpcPeeringConnectionId"),
        ("network_interface", "NetworkInterfaceId"),
        ("instance", "InstanceId"),
        ("egress_only_internet_gateway", "EgressOnlyInternetGatewayId"),
        ("carrier_gateway", "CarrierGatewayId"),
        ("local_gateway", "LocalGatewayId"),
        ("vpc_endpoint", "VpcEndpointId"),
    )
    target_type: str | None = None
    target_id: str | None = None
    for name, field in target_fields:
        value = route.get(field)
        if value:
            target_type, target_id = name, value
            break

    destination = (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
    )

    return {
        "destination": destination,
        "destination_cidr_block": route.get("DestinationCidrBlock"),
        "destination_ipv6_cidr_block": route.get("DestinationIpv6CidrBlock"),
        "destination_prefix_list_id": route.get("DestinationPrefixListId"),
        "target_type": target_type,
        "target_id": target_id,
        "state": route.get("State"),
        "origin": route.get("Origin"),
    }


def _is_internet_route(route: Mapping[str, Any]) -> bool:
    """A default route whose target is genuinely an internet gateway.

    Both halves are required. A default route to a NAT gateway provides
    outbound-only egress and no inbound reachability; treating it as an
    internet route would manufacture exposure that does not exist.
    """

    target = route.get("target_id") or ""
    return bool(
        route.get("destination") in DEFAULT_ROUTES
        and route.get("target_type") == "gateway"
        and target.startswith(_IGW_PREFIX)
    )


def normalize_route_table(
    *,
    route_table: Mapping[str, Any],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One route table, with routes and associations preserved in order.

    Emits ``CONNECTS_TO`` to each internet gateway it actually routes
    to — the first authoritative internet-egress evidence in the graph,
    replacing inference from "the instance has a public IP".
    """

    routes = [_normalize_route(route) for route in route_table.get("Routes", [])]

    associations = [
        {
            "association_id": association.get("RouteTableAssociationId"),
            "subnet_id": association.get("SubnetId"),
            "gateway_id": association.get("GatewayId"),
            "is_main": bool(association.get("Main", False)),
            "state": (association.get("AssociationState") or {}).get("State"),
        }
        for association in route_table.get("Associations", [])
    ]

    associated_subnet_ids = sorted(
        {a["subnet_id"] for a in associations if a["subnet_id"]}
    )
    internet_gateway_ids = sorted(
        {r["target_id"] for r in routes if _is_internet_route(r) and r["target_id"]}
    )

    attributes: dict[str, Any] = {
        "vpc_id": route_table.get("VpcId"),
        # The evidence, in the order AWS returned it.
        "routes": routes,
        "associations": associations,
        "associated_subnet_ids": associated_subnet_ids,
        # A route table is "main" when ANY association says so. A subnet
        # with no explicit association implicitly uses it — which is why
        # the absence of an association is not the absence of a route.
        "is_main": any(a["is_main"] for a in associations),
        # Derived, ALONGSIDE the routes above rather than instead of them.
        "has_internet_route": bool(internet_gateway_ids),
        "internet_gateway_ids": internet_gateway_ids,
    }

    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(gateway_id),
            relationship_type=RelationshipType.CONNECTS_TO,
            evidence={
                "source_field": "DescribeRouteTables.RouteTables[].Routes[].GatewayId",
                "destinations": sorted(
                    {
                        str(r["destination"])
                        for r in routes
                        if _is_internet_route(r) and r["target_id"] == gateway_id
                    }
                ),
            },
            confidence="high",
        )
        for gateway_id in internet_gateway_ids
    ) + tuple(
        # The subnet association, emitted from the route table because
        # that is the side AWS reports it on — the same rule that put
        # PROTECTS on the NACL rather than the subnet.
        #
        # `ATTACHED_TO` because an association is configuration binding,
        # not movement: an attacker does not travel from a route table
        # into a subnet. It is informational, and its value is that a
        # subnet rule can now traverse INCOMING to ask "does the route
        # table governing me reach the internet?" — which is the strong
        # evidence a `public subnet` finding needs, instead of the weak
        # `map_public_ip_on_launch` signal alone.
        ResourceRelationship(
            target_resource_id=ResourceId(subnet_id),
            relationship_type=RelationshipType.ATTACHED_TO,
            evidence={
                "source_field": (
                    "DescribeRouteTables.RouteTables[].Associations[].SubnetId"
                ),
                "has_internet_route": bool(internet_gateway_ids),
            },
            confidence="high",
        )
        for subnet_id in associated_subnet_ids
    )

    return _resource(
        resource_id=route_table["RouteTableId"],
        resource_type="aws_route_table",
        region=region,
        attributes=attributes,
        tags=_tags(route_table.get("Tags")),
        relationships=relationships,
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Internet gateway
# ---------------------------------------------------------------------


def normalize_internet_gateway(
    *,
    gateway: Mapping[str, Any],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One internet gateway, with ``ATTACHED_TO`` per available attachment.

    Only ``available`` attachments produce an edge. An attachment part
    way through attach or detach is not connectivity, and reporting it as
    such would put a transient state into a security conclusion. The full
    attachment list is preserved as evidence regardless of state.
    """

    attachments = [
        {"vpc_id": attachment.get("VpcId"), "state": attachment.get("State")}
        for attachment in gateway.get("Attachments", [])
    ]
    attached_vpc_ids = sorted(
        {a["vpc_id"] for a in attachments if a["vpc_id"] and a["state"] == "available"}
    )

    attributes: dict[str, Any] = {
        "attachments": attachments,
        "attached_vpc_ids": attached_vpc_ids,
        "is_attached": bool(attached_vpc_ids),
    }

    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(vpc_id),
            relationship_type=RelationshipType.ATTACHED_TO,
            evidence={
                "source_field": "DescribeInternetGateways.InternetGateways[].Attachments[]",
                "state": "available",
            },
            confidence="high",
        )
        for vpc_id in attached_vpc_ids
    )

    return _resource(
        resource_id=gateway["InternetGatewayId"],
        resource_type="aws_internet_gateway",
        region=region,
        attributes=attributes,
        tags=_tags(gateway.get("Tags")),
        relationships=relationships,
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Network ACL
# ---------------------------------------------------------------------


def _normalize_acl_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    port_range = entry.get("PortRange") or {}
    return {
        "rule_number": entry.get("RuleNumber"),
        # "-1" means "all protocols" in the AWS API. Kept verbatim rather
        # than translated, so the evidence matches what AWS returned.
        "protocol": entry.get("Protocol"),
        "rule_action": entry.get("RuleAction"),
        "cidr_block": entry.get("CidrBlock"),
        "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
        "port_from": port_range.get("From"),
        "port_to": port_range.get("To"),
        "icmp_type": (entry.get("IcmpTypeCode") or {}).get("Type"),
        "icmp_code": (entry.get("IcmpTypeCode") or {}).get("Code"),
    }


def normalize_network_acl(
    *,
    acl: Mapping[str, Any],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One network ACL, with entries kept **in rule-number order**.

    Order is load bearing: a NACL is evaluated lowest rule number first
    and stops at the first match, so a `DENY 100` before an `ALLOW 200`
    means something different from the reverse. Sorting by rule number
    also makes the output deterministic regardless of API ordering.

    Emits ``PROTECTS`` to each associated subnet — a control guarding a
    resource, which is what `PROTECTS` means. Note the direction differs
    from security groups, where the *instance* declares the attachment:
    AWS reports NACL associations on the NACL, so that is where the edge
    is emitted. Grounding each edge in whichever side AWS actually
    reports keeps it evidence-based rather than symmetric for its own
    sake.
    """

    def _key(entry: dict[str, Any]) -> tuple[int, int]:
        number = entry.get("rule_number")
        # A malformed entry with no rule number sorts last rather than
        # crashing the scan; it is still reported verbatim.
        return (0, number) if isinstance(number, int) else (1, 0)

    # Split on the raw entry's own `Egress` flag, then normalize — so the
    # direction is read from AWS's field rather than from list position.
    raw = acl.get("Entries", [])
    ingress = sorted(
        (_normalize_acl_entry(e) for e in raw if not e.get("Egress", False)), key=_key
    )
    egress = sorted(
        (_normalize_acl_entry(e) for e in raw if e.get("Egress", False)), key=_key
    )

    associations = [
        {
            "association_id": association.get("NetworkAclAssociationId"),
            "subnet_id": association.get("SubnetId"),
        }
        for association in acl.get("Associations", [])
    ]
    associated_subnet_ids = sorted(
        {a["subnet_id"] for a in associations if a["subnet_id"]}
    )

    attributes: dict[str, Any] = {
        "vpc_id": acl.get("VpcId"),
        "is_default": bool(acl.get("IsDefault", False)),
        "ingress_entries": ingress,
        "egress_entries": egress,
        "associations": associations,
        "associated_subnet_ids": associated_subnet_ids,
        # Derived, alongside the entries. Deliberately narrow: "there is
        # an allow-all-from-anywhere ingress rule", not "this NACL
        # permits the traffic". The second needs a stateless-evaluation
        # engine that does not exist, and claiming it would be a
        # conclusion we cannot defend.
        "has_unrestricted_ingress_rule": any(
            e["rule_action"] == "allow"
            and (e["cidr_block"] in DEFAULT_ROUTES or e["ipv6_cidr_block"] in DEFAULT_ROUTES)
            for e in ingress
        ),
    }

    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(subnet_id),
            relationship_type=RelationshipType.PROTECTS,
            evidence={
                "source_field": "DescribeNetworkAcls.NetworkAcls[].Associations[].SubnetId"
            },
            confidence="high",
        )
        for subnet_id in associated_subnet_ids
    )

    return _resource(
        resource_id=acl["NetworkAclId"],
        resource_type="aws_network_acl",
        region=region,
        attributes=attributes,
        tags=_tags(acl.get("Tags")),
        relationships=relationships,
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


__all__ = [
    "DEFAULT_ROUTES",
    "normalize_internet_gateway",
    "normalize_network_acl",
    "normalize_route_table",
    "normalize_subnet",
    "normalize_vpc",
]
