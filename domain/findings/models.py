"""The Finding entity — a pure domain model.

IMPORTANT: this is NOT modeled around the AI Core external contract.
Blueprint §26.5 documents that the AI Core integration boundary expects a
strict 11-field projection of a Finding, and that the internal Finding
carries additional fields the contract does not know about. That
projection is an Anti-Corruption Layer belonging to a later phase
(infrastructure/ai/serialization, blueprint §26.12) — it does not exist
here, is not referenced here, and this module has no notion of it.
Everything below exists because the Domain itself needs it: to know what
was found, on what resource, for which tenant, and why.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from domain.shared.enums import Severity
from domain.shared.errors import InvalidFinding
from domain.shared.identifiers import AttackPathId, FindingId, ResourceId, RuleId, TenantId
from domain.shared.temporal import is_timezone_aware


class FindingStatus(str, Enum):
    """Mirrors the three-valued outcome a rule evaluation produces
    (:class:`domain.rules.conditions.EvaluationResult`) at the Finding
    level: a violation (``FAIL``), a pass (``PASS``), or a result that
    could not be determined from the data collected (``INDETERMINATE``).
    """

    FAIL = "fail"
    PASS = "pass"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class Evidence:
    """The deterministic, collected facts backing a Finding — authoritative,
    as opposed to an AI-generated explanation (blueprint §26.7, a later
    phase). May be empty when a rule matched on presence/absence alone.
    """

    data: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.data, Mapping):
            raise InvalidFinding(f"Evidence.data must be a mapping, got {type(self.data).__name__}")
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))


def _validate_bounded_score(name: str, value: float | None) -> None:
    if value is None:
        return
    if not isinstance(value, (int, float)) or not (0 <= value <= 100):
        raise InvalidFinding(f"{name} must be between 0 and 100 when provided, got {value!r}")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single, tenant-scoped compliance finding: this resource, this
    rule, this outcome.

    Fields split into two groups by intent, not by mechanism — both live
    on the same entity because both are the Domain's business, but only
    the first group is meaningful outside this codebase:

    * Core finding data: ``id``, ``tenant_id``, ``resource_id``,
      ``rule_id``, ``framework``, ``control_id``, ``domain``, ``status``,
      ``severity``, ``evidence``, ``detected_at``.
    * Internal bookkeeping the Domain needs for its own lifecycle
      (scan provenance, versioning/supersession, cross-references to
      other domain aggregates, bounded risk/confidence annotations) that
      no external integration is entitled to assume the shape of.
    """

    id: FindingId
    tenant_id: TenantId
    resource_id: ResourceId
    rule_id: RuleId
    framework: str
    control_id: str
    domain: str
    status: FindingStatus
    severity: Severity
    evidence: Evidence
    detected_at: datetime

    # Internal-only domain fields (blueprint §26.5) — never assumed to
    # cross any external boundary as-is.
    scan_id: str | None = None
    rule_version: str | None = None
    region: str | None = None
    environment: str | None = None
    version: int = 1
    superseded_by: FindingId | None = None
    related_attack_path_ids: tuple[AttackPathId, ...] = ()
    related_drift_event_ids: tuple[str, ...] = ()
    risk: float | None = None
    confidence: float | None = None

    # Additive (Phase 3B — CSPM conformance design proposal, Part I:
    # Finding Identity). `id` remains the PHYSICAL, per-scan identity
    # (unique to one scan run — see application/rules/evaluate_rules.py
    # for exactly how it's derived). `logical_finding_id` is the STABLE
    # identity of "this rule, on this resource, for this tenant/account"
    # across repeated scans — the key the future exception/suppression
    # lifecycle and first_seen/last_seen tracking need, neither of which
    # exist yet (both explicitly out of scope for this phase). Optional
    # so no Phase 1/2 Finding(...) construction site breaks.
    account_id: str | None = None
    logical_finding_id: str | None = None

    # Additive (graph expansion §3 — finding contextualization). A
    # cross-resource finding used to say "EC2 instance attached to an
    # open security group" without naming WHICH security group: the rule
    # traversed the edge and discarded the traversal, throwing away the
    # one fact needed to act on the finding.
    #
    #: Resources whose state is part of why this rule reached its
    #: conclusion — the neighbours a relationship condition matched,
    #: sorted and deduplicated so the list is diffable between scans.
    #: Empty for single-resource rules, which is the honest value: they
    #: are related to nothing.
    related_resources: tuple[str, ...] = ()
    #: Neighbours whose contribution could NOT be determined, kept apart
    #: from ``related_resources`` so a data gap is never presented as a
    #: confirmed relationship.
    indeterminate_resources: tuple[str, ...] = ()
    #: The subject's graph neighbourhood, attached only when the rule
    #: actually traversed the graph. Attaching it to every
    #: single-resource finding would bloat every row for no signal.
    graph_context: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, FindingId):
            raise InvalidFinding("id must be a FindingId")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidFinding("tenant_id must be a TenantId")
        if not isinstance(self.resource_id, ResourceId):
            raise InvalidFinding("resource_id must be a ResourceId")
        if not isinstance(self.rule_id, RuleId):
            raise InvalidFinding("rule_id must be a RuleId")
        for name in ("framework", "control_id", "domain"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidFinding(f"{name} must be a non-blank string")
        if not isinstance(self.status, FindingStatus):
            raise InvalidFinding("status must be a FindingStatus")
        if not isinstance(self.severity, Severity):
            raise InvalidFinding("severity must be a Severity")
        if not isinstance(self.evidence, Evidence):
            raise InvalidFinding("evidence must be an Evidence instance")
        if not isinstance(self.detected_at, datetime):
            raise InvalidFinding("detected_at must be a datetime")
        if not is_timezone_aware(self.detected_at):
            raise InvalidFinding("detected_at must be timezone-aware")
        if not isinstance(self.version, int) or self.version < 1:
            raise InvalidFinding("version must be a positive integer")
        if self.superseded_by is not None:
            if not isinstance(self.superseded_by, FindingId):
                raise InvalidFinding("superseded_by must be a FindingId")
            if self.superseded_by == self.id:
                raise InvalidFinding("a finding cannot supersede itself")

        _validate_bounded_score("risk", self.risk)
        _validate_bounded_score("confidence", self.confidence)

        if self.account_id is not None and not self.account_id.strip():
            raise InvalidFinding("account_id must be None or a non-blank string")
        if self.logical_finding_id is not None and not self.logical_finding_id.strip():
            raise InvalidFinding("logical_finding_id must be None or a non-blank string")

        for name in ("related_resources", "indeterminate_resources"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not all(
                isinstance(v, str) and v.strip() for v in value
            ):
                raise InvalidFinding(f"{name} must be a tuple of non-blank strings")
            # Sorted and deduplicated is an invariant, not a convention:
            # a finding whose related list reorders between two scans of
            # unchanged infrastructure cannot be diffed, and the whole
            # point of naming these resources is that a human compares
            # them across runs.
            if list(value) != sorted(set(value)):
                raise InvalidFinding(f"{name} must be sorted and free of duplicates")

        if self.graph_context is not None:
            if not isinstance(self.graph_context, Mapping):
                raise InvalidFinding("graph_context must be a mapping when provided")
            object.__setattr__(self, "graph_context", MappingProxyType(dict(self.graph_context)))
