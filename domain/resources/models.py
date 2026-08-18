"""The canonical resource model (blueprint §8).

``NormalizedResource`` is the single shape every cloud provider's raw API
response is collapsed into before anything else in the Domain sees it.
``resource_type`` is intentionally left as a provider-specific free string
(e.g. ``"s3_bucket"``) rather than an abstracted category — blueprint §8
explicitly rejects introducing a canonical category enum before a second
provider (Azure) exists to prove the mapping is needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import InvalidResource, InvalidResourceRelationship
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.temporal import is_timezone_aware


@dataclass(frozen=True, slots=True)
class ResourceRelationship:
    """A relationship from the owning resource to another resource, as
    produced by a collector. The relationship vocabulary is the same
    closed set used by ``graph.GraphEdge`` (blueprint §10) — defined once
    in ``domain.shared.enums.RelationshipType``.
    """

    target_resource_id: ResourceId
    relationship_type: RelationshipType

    # --- Provenance (additive; both default, so every existing
    # two-argument construction is unchanged).
    #
    # These exist because a collector often knows WHY it asserted a
    # relationship, and that reason was previously discarded:
    # ``BuildResourceGraph`` synthesized a generic evidence dict and the
    # collector's specific knowledge never reached the graph. An edge
    # that cannot show its reasoning is an edge a security engineer can
    # neither trust nor dismiss.

    #: Observed values justifying this relationship. Small mapping of
    #: collected facts, never prose.
    evidence: Mapping[str, Any] = field(default_factory=dict)
    #: How sure the collector is, using the graph vocabulary. ``None``
    #: means "no opinion" and lets the graph apply its own default.
    confidence: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.relationship_type, RelationshipType):
            raise InvalidResourceRelationship(
                f"relationship_type must be a RelationshipType, got {self.relationship_type!r}"
            )
        if not isinstance(self.evidence, Mapping):
            raise InvalidResourceRelationship("evidence must be a mapping")
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))
        if self.confidence is not None and self.confidence not in (
            "high",
            "medium",
            "low",
            "unknown",
        ):
            raise InvalidResourceRelationship(
                f"confidence must be high/medium/low/unknown or None, got {self.confidence!r}"
            )


def _immutable_mapping(data: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise InvalidResource(f"expected a mapping, got {type(data).__name__}")
    return MappingProxyType(dict(data))


@dataclass(frozen=True, slots=True)
class NormalizedResource:
    """The canonical resource representation (blueprint §8).

    ``attributes`` is intentionally free-form (ADR-003): provider-specific
    data is preserved without coupling the Domain to a cloud SDK schema.
    """

    resource_id: ResourceId
    resource_type: str
    cloud_provider: CloudProvider
    tenant_id: TenantId
    region: str | None
    attributes: Mapping[str, Any]
    tags: Mapping[str, str]
    relationships: tuple[ResourceRelationship, ...]
    collected_at: datetime

    # Additive (Phase 3B): the cloud account this resource lives in —
    # distinct from tenant_id, since one tenant can own multiple cloud
    # accounts. Optional/defaulted so no Phase 1/2 construction site
    # breaks; a real AWS collector populates it via STS. Without it,
    # two different accounts' resources sharing an AWS-assigned ID
    # (e.g. "sg-0123456789abcdef0", account-scoped, not globally unique)
    # are not distinguishable — see docs/architecture/phase-3-rules.md,
    # Known Limitations, for what this does and does not fix.
    account_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.resource_id, ResourceId):
            raise InvalidResource("resource_id must be a ResourceId")
        if not isinstance(self.resource_type, str) or not self.resource_type.strip():
            raise InvalidResource("resource_type must be a non-blank string")
        if not isinstance(self.cloud_provider, CloudProvider):
            raise InvalidResource("cloud_provider must be a CloudProvider")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidResource("tenant_id must be a TenantId")
        if self.region is not None and not self.region.strip():
            raise InvalidResource("region must be None or a non-blank string")
        if self.account_id is not None and not self.account_id.strip():
            raise InvalidResource("account_id must be None or a non-blank string")
        if not isinstance(self.collected_at, datetime):
            raise InvalidResource("collected_at must be a datetime")
        if not is_timezone_aware(self.collected_at):
            raise InvalidResource("collected_at must be timezone-aware")
        for relationship in self.relationships:
            if not isinstance(relationship, ResourceRelationship):
                raise InvalidResource(
                    "relationships must contain only ResourceRelationship instances"
                )

        object.__setattr__(self, "attributes", _immutable_mapping(self.attributes))
        object.__setattr__(self, "tags", _immutable_mapping(self.tags))
