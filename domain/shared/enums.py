"""Enumerations shared across Domain modules.

Kept in ``shared/`` (rather than duplicated in ``resources/`` and
``graph/``) so that ``ResourceRelationship`` (resources/) and
``GraphEdge`` (graph/) can reference the same closed relationship
vocabulary without ``resources/`` depending on ``graph/``.
"""

from __future__ import annotations

from enum import Enum


class CloudProvider(str, Enum):
    """Cloud providers the platform can normalize resources from.

    AWS is CURRENT (collectors exist per the blueprint's target
    architecture); AZURE is DESIGNED — no collector exists yet, but the
    Domain must already be able to represent an Azure-sourced resource
    without a rewrite (blueprint §7, ADR-002).
    """

    AWS = "aws"
    AZURE = "azure"


class RelationshipType(str, Enum):
    """Closed vocabulary of graph relationship types (blueprint §10).

    Each value is justified by a real collection capability described in
    the blueprint — this enum must never be extended speculatively.
    """

    CONTAINS = "contains"
    CONNECTS_TO = "connects_to"
    PROTECTS = "protects"
    ALLOWS = "allows"
    ASSUMES = "assumes"
    ACCESSES = "accesses"
    ATTACHED_TO = "attached_to"
    PUBLICLY_EXPOSED = "publicly_exposed"


class Severity(str, Enum):
    """Static severity of a rule violation ("how serious is this in the
    abstract") — distinct from ``RiskScore`` (contextual) and
    ``ConfidenceScore`` (data reliability). See blueprint §13.

    Vocabulary fixed to the four values confirmed by the Core↔AI Service
    integration handoff (no ``INFO``) — Phase 1's original plan flagged
    this as an open ambiguity (blueprint §13 gives no enumeration) and
    used a 5-level placeholder; this replaces it with the authoritative
    external vocabulary now that it is known, rather than carrying two
    divergent severity scales.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    """How reliable a *rule's* detection method is — distinct from
    ``ConfidenceScore`` (domain.risk), which measures reliability of the
    *collected data* a finding was built from. ``Confidence`` measures
    reliability of the *rule's own logic*: a rule reading one explicit
    boolean field (e.g. ``versioning_enabled``) is HIGH confidence; a
    rule inferring a security posture from indirect signals is lower.
    Not currently consumed by any evaluator logic — a catalog metadata
    field only, for a human reviewing rule quality (Phase 3B brief,
    Part F).
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
