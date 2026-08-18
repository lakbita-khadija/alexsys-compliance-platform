"""AWS network topology collectors (STEP 8A).

Five collectors over one `ec2` client: VPC, subnet, route table,
internet gateway and network ACL.

They follow the existing per-service pattern exactly — the same base
class, the same paginator use, the same `translate_client_error` →
`AwsCollectionError` wrapping — so a failure here is indistinguishable
in shape from a failure in `SecurityGroupCollector`, and
`AwsCollector.collect()` isolates each one the same way.

**One deliberate asymmetry.** `VpcCollector` calls `DescribeSubnets` in
addition to `DescribeVpcs`, because AWS reports VPC membership on the
subnet while the `CONTAINS` edge points container → contained. The
alternative was inventing a `BELONGS_TO` relationship type, which the
closed vocabulary forbids. The cost is one extra API call; the audit
(§3.6) records the reasoning.

If that extra call is denied, the VPC is still collected and simply
emits no containment edges. Absence of an edge means "not observed",
never "no subnets" — the same discipline the rest of the graph keeps.
"""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.network import (
    normalize_internet_gateway,
    normalize_network_acl,
    normalize_route_table,
    normalize_subnet,
    normalize_vpc,
)
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector

logger = logging.getLogger(__name__)


class _Ec2PaginatedCollector(AwsResourceCollector):
    """Shared plumbing for the five `describe_*` paginated calls."""

    #: boto3 paginator name, e.g. "describe_vpcs".
    operation: str = ""
    #: Key holding the list in each page, e.g. "Vpcs".
    result_key: str = ""

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("ec2")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context=f"collecting {self.resource_type}")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _pages(self, client, operation: str, result_key: str) -> list[dict]:
        return [
            item
            for page in client.get_paginator(operation).paginate()
            for item in page.get(result_key, [])
        ]

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        items = self._pages(client, self.operation, self.result_key)
        return tuple(self._normalize(item, region, collected_at) for item in items)

    def _normalize(self, item: dict, region, collected_at) -> NormalizedResource:  # pragma: no cover - abstract
        raise NotImplementedError


class VpcCollector(_Ec2PaginatedCollector):
    """VPCs, plus `CONTAINS` edges to the subnets they hold."""

    resource_type = "VPCs"
    operation = "describe_vpcs"
    result_key = "Vpcs"

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        vpcs = self._pages(client, self.operation, self.result_key)

        subnet_ids_by_vpc = self._subnet_ids_by_vpc(client)

        return tuple(
            normalize_vpc(
                vpc=vpc,
                # Indexed, not `.get`: a VPC response without a VpcId is
                # not a VPC, and the normalizer would raise on it
                # anyway. Matches how every other collector reads its id.
                subnet_ids=subnet_ids_by_vpc.get(vpc["VpcId"], ()),
                region=region,
                tenant_id=self._tenant_id,
                collected_at=collected_at,
                account_id=self._account_id,
            )
            for vpc in vpcs
        )

    def _subnet_ids_by_vpc(self, client) -> dict[str, list[str]]:
        """Subnet membership, or nothing if we are not allowed to look.

        Denied here is NOT fatal: the VPCs themselves were collected and
        are worth reporting. What must not happen is a VPC reported as
        containing nothing when we simply could not see — so the failure
        is logged, and the resulting absence of edges carries the usual
        "not observed" meaning rather than a claim.
        """

        try:
            subnets = self._pages(client, "describe_subnets", "Subnets")
        except ClientError as exc:
            logger.warning(
                "could not enumerate subnets for VPC containment edges: %s",
                translate_client_error(exc, context="collecting subnets for VPC containment"),
            )
            return {}

        by_vpc: dict[str, list[str]] = {}
        for subnet in subnets:
            vpc_id, subnet_id = subnet.get("VpcId"), subnet.get("SubnetId")
            if vpc_id and subnet_id:
                by_vpc.setdefault(vpc_id, []).append(subnet_id)
        return by_vpc


class SubnetCollector(_Ec2PaginatedCollector):
    """Subnets. Emits no relationships — see the normalizer."""

    resource_type = "subnets"
    operation = "describe_subnets"
    result_key = "Subnets"

    def _normalize(self, item, region, collected_at) -> NormalizedResource:
        return normalize_subnet(
            subnet=item,
            region=region,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


class RouteTableCollector(_Ec2PaginatedCollector):
    """Route tables, with routes preserved and `CONNECTS_TO` to real IGWs."""

    resource_type = "route tables"
    operation = "describe_route_tables"
    result_key = "RouteTables"

    def _normalize(self, item, region, collected_at) -> NormalizedResource:
        return normalize_route_table(
            route_table=item,
            region=region,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


class InternetGatewayCollector(_Ec2PaginatedCollector):
    """Internet gateways, with `ATTACHED_TO` per available attachment."""

    resource_type = "internet gateways"
    operation = "describe_internet_gateways"
    result_key = "InternetGateways"

    def _normalize(self, item, region, collected_at) -> NormalizedResource:
        return normalize_internet_gateway(
            gateway=item,
            region=region,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


class NetworkAclCollector(_Ec2PaginatedCollector):
    """Network ACLs, with ordered entries and `PROTECTS` per subnet."""

    resource_type = "network ACLs"
    operation = "describe_network_acls"
    result_key = "NetworkAcls"

    def _normalize(self, item, region, collected_at) -> NormalizedResource:
        return normalize_network_acl(
            acl=item,
            region=region,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


__all__ = [
    "InternetGatewayCollector",
    "NetworkAclCollector",
    "RouteTableCollector",
    "SubnetCollector",
    "VpcCollector",
]
