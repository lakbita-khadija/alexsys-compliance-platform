"""External contract DTOs for the Core <-> AI Service boundary.

These are boundary/translation models, not Domain entities (blueprint
§26.5, §26.12: the ACL/serialization layer). They exist so a ``Finding``
or ``NormalizedResource`` can be projected into *exactly* the shape the
AI Service's integration handoff specifies — no more, no less — without
the Domain entity itself ever being shaped around that contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from contracts.ai_service.enums import ExternalFindingStatus, Framework, RiskDomain
from contracts.errors import ContractTranslationError
from domain.shared.enums import CloudProvider, Severity
from domain.shared.temporal import is_timezone_aware


def _require_non_blank(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractTranslationError(f"{name} must be a non-blank string, got {value!r}")


def _require_timezone_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or not is_timezone_aware(value):
        raise ContractTranslationError(f"{name} must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class FindingContract:
    """The AI Service's authoritative Finding contract — exactly these
    11 fields, no more. ``to_payload()`` produces the exact JSON-safe
    dict the AI Service expects; the AI Service rejects unknown/extra
    fields, so no internal Domain field (``risk``, ``confidence``,
    ``scan_id``, ...) is reachable from this type at all.
    """

    id: str
    tenant_id: str
    resource_id: str
    rule_id: str
    framework: Framework
    control_id: str
    domain: RiskDomain
    status: ExternalFindingStatus
    severity: Severity
    evidence: Mapping[str, Any]
    detected_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "tenant_id", "resource_id", "rule_id", "control_id"):
            _require_non_blank(name, getattr(self, name))
        if not isinstance(self.framework, Framework):
            raise ContractTranslationError("framework must be a Framework")
        if not isinstance(self.domain, RiskDomain):
            raise ContractTranslationError("domain must be a RiskDomain")
        if not isinstance(self.status, ExternalFindingStatus):
            raise ContractTranslationError("status must be an ExternalFindingStatus")
        if not isinstance(self.severity, Severity):
            raise ContractTranslationError("severity must be a Severity")
        if not isinstance(self.evidence, Mapping):
            raise ContractTranslationError("evidence must be a mapping")
        _require_timezone_aware("detected_at", self.detected_at)

        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    def to_payload(self) -> dict[str, Any]:
        """The exact JSON-serializable payload the AI Service contract
        expects — exactly 11 keys, matching field-for-field.
        """

        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "resource_id": self.resource_id,
            "rule_id": self.rule_id,
            "framework": self.framework.value,
            "control_id": self.control_id,
            "domain": self.domain.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": dict(self.evidence),
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class NormalizedResourceContract:
    """The AI Service's NormalizedResource contract — exactly these 8
    fields, using the handoff's exact field names (which differ from the
    Domain's ``NormalizedResource`` field names by design; see
    ``contracts.ai_service.translation``).
    """

    id: str
    tenant_id: str
    cloud: CloudProvider
    service: str
    region: str | None
    type: str
    config: Mapping[str, Any]
    collected_at: datetime

    def __post_init__(self) -> None:
        for name in ("id", "tenant_id", "service", "type"):
            _require_non_blank(name, getattr(self, name))
        if self.region is not None:
            _require_non_blank("region", self.region)
        if not isinstance(self.cloud, CloudProvider):
            raise ContractTranslationError("cloud must be a CloudProvider")
        if not isinstance(self.config, Mapping):
            raise ContractTranslationError("config must be a mapping")
        _require_timezone_aware("collected_at", self.collected_at)

        object.__setattr__(self, "config", MappingProxyType(dict(self.config)))

    def to_payload(self) -> dict[str, Any]:
        """The exact JSON-serializable payload — exactly 8 keys."""

        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "cloud": self.cloud.value,
            "service": self.service,
            "region": self.region,
            "type": self.type,
            "config": dict(self.config),
            "collected_at": self.collected_at.isoformat(),
        }
