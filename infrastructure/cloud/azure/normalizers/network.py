"""Azure Network Security Group -> ``NormalizedResource``.

The Azure counterpart of ``normalizers/security_group.py``, and it
follows exactly the same principle: "which ports are sensitive" is a
RULE concern, never an Infrastructure one. This module only reports the
factual ``unrestricted_ingress_ports`` and ``has_unrestricted_ingress``;
``rules/azure/network.yaml`` decides which of those ports matter.

Azure NSG rules differ from AWS security groups in three ways this
module normalizes away:

* NSGs have explicit Allow AND Deny rules with a numeric ``priority``
  (lower wins); AWS security groups are allow-only. Only ``Allow``
  rules are considered here — a Deny rule cannot expose anything.
* The "any source" wildcard is ``"*"``, ``"Internet"``, or
  ``"0.0.0.0/0"``, where AWS has only the CIDR form.
* A rule can carry a port RANGE (``"22"``, ``"22-25"``, or ``"*"``),
  and can list several in ``destination_port_ranges``. Single ports are
  enumerated into ``unrestricted_ingress_ports``; ranges and ``"*"``
  set ``has_unrestricted_ingress`` without being expanded — the same
  documented single-port-only limitation the AWS normalizer has.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId

_UNRESTRICTED_SOURCES = frozenset({"*", "internet", "0.0.0.0/0", "::/0", "any"})


def _is_unrestricted_source(rule: Mapping[str, Any]) -> bool:
    sources = [rule.get("source_address_prefix")]
    sources.extend(rule.get("source_address_prefixes") or [])
    return any(str(source).strip().lower() in _UNRESTRICTED_SOURCES for source in sources if source)


def _port_ranges(rule: Mapping[str, Any]) -> list[str]:
    ranges = [rule.get("destination_port_range")]
    ranges.extend(rule.get("destination_port_ranges") or [])
    return [str(r) for r in ranges if r]


def analyze_security_rules(rules: Iterable[Mapping[str, Any]]) -> tuple[bool, tuple[int, ...]]:
    """Returns ``(has_unrestricted_ingress, unrestricted_single_ports)``.

    Only inbound ``Allow`` rules from an unrestricted source count.
    """

    has_unrestricted = False
    single_ports: list[int] = []

    for rule in rules:
        if str(rule.get("direction", "")).lower() != "inbound":
            continue
        if str(rule.get("access", "")).lower() != "allow":
            continue
        if not _is_unrestricted_source(rule):
            continue

        has_unrestricted = True
        for port_range in _port_ranges(rule):
            if port_range.isdigit():
                single_ports.append(int(port_range))

    return has_unrestricted, tuple(single_ports)


def normalize_network_security_group(
    *,
    resource_id: str,
    name: str,
    location: str,
    security_rules: Sequence[Mapping[str, Any]],
    tags: Mapping[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    has_unrestricted_ingress, unrestricted_ingress_ports = analyze_security_rules(security_rules)

    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="azure_network_security_group",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        region=location,
        attributes={
            "name": name,
            "has_unrestricted_ingress": has_unrestricted_ingress,
            "unrestricted_ingress_ports": unrestricted_ingress_ports,
            "security_rule_count": len(security_rules),
        },
        tags=dict(tags),
        relationships=(),
        collected_at=collected_at,
        account_id=account_id,
    )
