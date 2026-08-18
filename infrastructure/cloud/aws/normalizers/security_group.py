"""AWS Security Group -> ``NormalizedResource`` (blueprint §6: CURRENT).

"Is 0.0.0.0/0 exposed on a sensitive port" (blueprint §15's
compliant/non-compliant pair) is deliberately NOT decided here —
"sensitive port" is a rule concern, not an Infrastructure fact.
Normalization only reports the plain, factual
``unrestricted_ingress_ports`` (single-port ingress rules open to
0.0.0.0/0 or ::/0) and ``has_unrestricted_ingress`` (true for any
world-open rule, including port ranges/"all traffic" rules that aren't
expanded into individual ports) — Rules decide which of those ports
matter.

Security-group-to-security-group references (``UserIdGroupPairs``)
become ``ALLOWS`` relationships to the *referenced* group — a real,
already-collected resource, unlike the ``PUBLICLY_EXPOSED``/
``__internet__`` case documented in ``normalizers/s3.py``.
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId

_UNRESTRICTED_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _rule_cidrs(rule: dict) -> set[str]:
    cidrs = {entry["CidrIp"] for entry in rule.get("IpRanges", [])}
    cidrs |= {entry["CidrIpv6"] for entry in rule.get("Ipv6Ranges", [])}
    return cidrs


def _is_unrestricted(rule: dict) -> bool:
    return bool(_rule_cidrs(rule) & _UNRESTRICTED_CIDRS)


def _single_port(rule: dict) -> int | None:
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is not None and from_port == to_port:
        return from_port
    return None


def analyze_ingress_rules(ingress_rules: list[dict]) -> tuple[bool, tuple[int, ...]]:
    """Returns ``(has_unrestricted_ingress, unrestricted_single_ports)``."""

    has_unrestricted = False
    single_ports: list[int] = []
    for rule in ingress_rules:
        if not _is_unrestricted(rule):
            continue
        has_unrestricted = True
        port = _single_port(rule)
        if port is not None:
            single_ports.append(port)
    return has_unrestricted, tuple(single_ports)


def extract_allows_relationships(ingress_rules: list[dict]) -> tuple[ResourceRelationship, ...]:
    relationships = []
    for rule in ingress_rules:
        for pair in rule.get("UserIdGroupPairs", []):
            relationships.append(
                ResourceRelationship(
                    target_resource_id=ResourceId(pair["GroupId"]),
                    relationship_type=RelationshipType.ALLOWS,
                )
            )
    return tuple(relationships)


def normalize_security_group(
    *,
    group_id: str,
    vpc_id: str | None,
    region: str,
    ingress_rules: list[dict],
    egress_rules: list[dict],
    tags: dict[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    has_unrestricted_ingress, unrestricted_ingress_ports = analyze_ingress_rules(ingress_rules)

    return NormalizedResource(
        resource_id=ResourceId(group_id),
        resource_type="security_group",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes={
            "vpc_id": vpc_id,
            "has_unrestricted_ingress": has_unrestricted_ingress,
            "unrestricted_ingress_ports": unrestricted_ingress_ports,
            "ingress_rule_count": len(ingress_rules),
            "egress_rule_count": len(egress_rules),
        },
        tags=tags,
        relationships=extract_allows_relationships(ingress_rules),
        collected_at=collected_at,
        account_id=account_id,
    )
