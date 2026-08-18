"""Drift domain model (blueprint §12).

Independent of persistence: everything here operates on in-memory data.
Storing/retrieving historical snapshots (``ResourceSnapshot``) is a
``infrastructure/persistence/`` concern for a later phase — never mixed
into the Domain (blueprint §12).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from domain.shared.errors import InvalidDriftEvent
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.temporal import is_timezone_aware


class DriftType(str, Enum):
    """What kind of change was observed between two snapshots of a
    resource fleet.
    """

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass(frozen=True, slots=True)
class DriftEvent:
    """A single observed change for one resource between two scans."""

    resource_id: ResourceId
    tenant_id: TenantId
    drift_type: DriftType
    changed_fields: Mapping[str, tuple[Any, Any]]
    detected_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.resource_id, ResourceId):
            raise InvalidDriftEvent("resource_id must be a ResourceId")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidDriftEvent("tenant_id must be a TenantId")
        if not isinstance(self.drift_type, DriftType):
            raise InvalidDriftEvent("drift_type must be a DriftType")
        if not isinstance(self.detected_at, datetime):
            raise InvalidDriftEvent("detected_at must be a datetime")
        if not is_timezone_aware(self.detected_at):
            raise InvalidDriftEvent("detected_at must be timezone-aware")
        if self.drift_type is DriftType.MODIFIED and not self.changed_fields:
            raise InvalidDriftEvent("a MODIFIED DriftEvent requires at least one changed field")

        object.__setattr__(self, "changed_fields", MappingProxyType(dict(self.changed_fields)))
