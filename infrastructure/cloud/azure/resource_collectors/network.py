"""Azure Network Security Group collection."""

from __future__ import annotations

from typing import Any

from domain.resources.models import NormalizedResource
from infrastructure.cloud.azure.errors import AzureCollectionError, translate_azure_error
from infrastructure.cloud.azure.normalizers.network import normalize_network_security_group
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector


class NetworkSecurityGroupCollector(AzureResourceCollector):
    """Collects every network security group in the subscription."""

    resource_type = "network security groups"

    def collect(self) -> tuple[NormalizedResource, ...]:
        try:
            return self._collect()
        except Exception as exc:
            cause = translate_azure_error(exc, context="collecting network security groups")
            raise AzureCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        groups = list(self._clients.network.network_security_groups.list_all())
        return tuple(self._normalize(group, collected_at) for group in groups)

    def _normalize(self, group, collected_at) -> NormalizedResource:
        rules = [_rule_to_mapping(rule) for rule in (getattr(group, "security_rules", None) or [])]
        return normalize_network_security_group(
            resource_id=group.id,
            name=getattr(group, "name", "") or "",
            location=getattr(group, "location", "") or "",
            security_rules=rules,
            tags=dict(getattr(group, "tags", None) or {}),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )


def _rule_to_mapping(rule) -> dict[str, Any]:
    """Flattens an SDK ``SecurityRule`` object into the plain mapping
    the normalizer expects, so the normalizer stays free of SDK types
    and is trivially testable with dict literals.
    """

    return {
        "name": getattr(rule, "name", None),
        "direction": _enum_value(getattr(rule, "direction", None)),
        "access": _enum_value(getattr(rule, "access", None)),
        "protocol": _enum_value(getattr(rule, "protocol", None)),
        "priority": getattr(rule, "priority", None),
        "source_address_prefix": getattr(rule, "source_address_prefix", None),
        "source_address_prefixes": list(getattr(rule, "source_address_prefixes", None) or []),
        "destination_port_range": getattr(rule, "destination_port_range", None),
        "destination_port_ranges": list(getattr(rule, "destination_port_ranges", None) or []),
    }


def _enum_value(value):
    return getattr(value, "value", value)
