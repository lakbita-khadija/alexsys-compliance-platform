"""Attack path domain objects (blueprint §11).

An ``AttackPath`` answers a different question than a ``Finding``: not
"does this resource violate this rule" but "does this combination of
findings, in this graph context, constitute a composite risk". It is
kept as its own aggregate, with its own ``algorithm_version``, because
the discovery/scoring algorithm evolves independently of the Rule
Engine (ADR-006).

``risk_score`` is accepted as an already-computed input and validated
here, never derived — the aggregate enforces bounds and the "blocked
path scores 0" invariant, while ``domain/attack_paths/scoring.py`` owns
the model that produces the number. Keeping those apart means the
scoring weights can change without touching the aggregate's invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from domain.graph.models import GraphEdge, GraphNode
from domain.shared.enums import Severity
from domain.shared.errors import InvalidAttackPath
from domain.shared.identifiers import AttackPathId, FindingId, TenantId


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A named attack technique contributing to a path (e.g. a MITRE-style
    identifier). No built-in catalog — the blueprint does not specify one
    (§11); this is an open value object, not a closed enum.
    """

    id: str
    name: str

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise InvalidAttackPath("AttackTechnique.id must be a non-blank string")
        if not self.name or not self.name.strip():
            raise InvalidAttackPath("AttackTechnique.name must be a non-blank string")


@dataclass(frozen=True, slots=True)
class AttackPath:
    """A composite, tenant-scoped attack path through a ``ResourceGraph``."""

    id: AttackPathId
    tenant_id: TenantId
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    contributing_finding_ids: tuple[FindingId, ...]
    attack_techniques: tuple[AttackTechnique, ...]
    severity: Severity
    risk_score: float
    algorithm_version: str

    # --- Additive (attack path phase). Every field defaults, so the
    # nine-argument construction used by the Phase 1 tests still works.

    #: Which analyzer scenario produced this path. Lets a consumer filter
    #: and a reader understand the claim without re-deriving it.
    scenario: str = ""
    #: Weakest-link confidence over every node and edge, using the GRAPH
    #: confidence vocabulary (high/medium/low/unknown). Deliberately not
    #: a fourth confidence system — see the current-state audit §3.
    confidence: str = "high"
    #: WHY this path is dangerous: the observed facts, the scoring
    #: breakdown, the readable chain. A path that cannot explain itself
    #: is a path nobody will act on.
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.nodes:
            raise InvalidAttackPath("an AttackPath must contain at least one node")
        if not isinstance(self.algorithm_version, str) or not self.algorithm_version.strip():
            raise InvalidAttackPath("algorithm_version must be a non-blank string")
        if not isinstance(self.severity, Severity):
            raise InvalidAttackPath("severity must be a Severity")
        if not isinstance(self.risk_score, (int, float)) or not (0 <= self.risk_score <= 100):
            raise InvalidAttackPath(
                f"risk_score must be between 0 and 100, got {self.risk_score!r}"
            )

        node_ids = {node.resource_id for node in self.nodes}
        for node in self.nodes:
            if node.tenant_id != self.tenant_id:
                raise InvalidAttackPath(
                    f"node {node.resource_id!s} belongs to tenant {node.tenant_id!s}, "
                    f"not {self.tenant_id!s} (tenant isolation)"
                )

        for edge in self.edges:
            if edge.source_id not in node_ids or edge.target_id not in node_ids:
                raise InvalidAttackPath(
                    f"edge {edge.source_id!s} -> {edge.target_id!s} references a node "
                    "not present in this AttackPath (path integrity)"
                )

        blocked = any(edge.blocked for edge in self.edges)
        if blocked and self.risk_score != 0:
            raise InvalidAttackPath("a blocked attack path must have risk_score == 0")

        if self.confidence not in ("high", "medium", "low", "unknown"):
            raise InvalidAttackPath(
                f"confidence must be high/medium/low/unknown, got {self.confidence!r}"
            )
        if not isinstance(self.evidence, Mapping):
            raise InvalidAttackPath("evidence must be a mapping")
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))
        if not isinstance(self.scenario, str):
            raise InvalidAttackPath("scenario must be a string")

    @property
    def is_blocked(self) -> bool:
        """Whether any edge on this path is prevented in practice."""

        return any(edge.blocked for edge in self.edges)

    @property
    def entry_point(self) -> GraphNode:
        """Where the attacker starts."""

        return self.nodes[0]

    @property
    def target(self) -> GraphNode:
        """What the attacker reaches."""

        return self.nodes[-1]
