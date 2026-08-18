"""Attack path risk scoring and severity mapping.

**This is an explainable product risk score, not a mathematically
authoritative one.** The weights below are a documented product
judgement about which security facts matter more than others. They are
not derived from incident data, they are not calibrated against any
published model, and nothing here should be presented to a customer as
objective truth. What they *are* is deterministic, inspectable, and
changeable in one place.

That honesty is the design constraint, not a disclaimer bolted on
afterwards. A CSPM that hands out a confident 87.4 it cannot explain
teaches its users to ignore the number. Every contribution here can be
traced to a named graph fact, and the score carries the factor breakdown
that produced it.

Deliberately not machine learning, and deliberately not a single opaque
formula (§8). The shape is:

    risk = exposure + privilege + sensitivity + relationship
           - confidence penalty - incompleteness penalty

clamped to [0, 100].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from domain.shared.enums import Severity

#: Bumped whenever any weight or threshold below changes, so a stored
#: score is never silently reinterpreted under a different model — the
#: same reasoning as ``RiskScore.model_version``.
SCORING_MODEL_VERSION = "apsm-1.0"

# ---------------------------------------------------------------------
# Weights. Every one of these is a product decision, stated as a number
# so it can be argued with. Grouped by the question it answers.
# ---------------------------------------------------------------------

#: "Can someone outside reach it at all?" The largest single
#: contribution, because internet reachability is what separates a
#: misconfiguration from an incident.
EXPOSURE_DIRECT_INTERNET_EDGE = 40.0
#: Exposure asserted by the resource's own attributes (a public bucket)
#: rather than by a graph edge. Slightly lower: an attribute is one
#: collector's reading, an edge is a modelled relationship.
EXPOSURE_ATTRIBUTE_EVIDENCE = 35.0
#: A network control that admits the whole internet, on the path.
EXPOSURE_UNRESTRICTED_INGRESS = 15.0

#: "How much can the attacker do once there?" Administrator access and a
#: privilege-escalation path are not additive beyond this cap — two ways
#: to reach total control is still total control.
PRIVILEGE_ADMINISTRATOR = 30.0
PRIVILEGE_ESCALATION_PATH = 20.0
PRIVILEGE_WILDCARD_ACTION = 10.0
PRIVILEGE_CAP = 30.0

#: "Is what they reach worth anything?"
SENSITIVITY_SECRETS = 25.0
SENSITIVITY_STORAGE = 20.0
SENSITIVITY_IDENTITY = 20.0
SENSITIVITY_AUDIT_LOG = 15.0

#: "Is the relationship itself dangerous?" ASSUMES means taking on an
#: identity, which is qualitatively worse than reading through one.
RELATIONSHIP_ASSUMES = 10.0
RELATIONSHIP_ACCESSES = 5.0

#: Longer chains need more to go right for the attacker. A small
#: discount per hop beyond the first, floored so a long path never
#: becomes free.
LENGTH_DISCOUNT_PER_HOP = 5.0
LENGTH_DISCOUNT_MAX = 15.0

#: "How much do we trust any of this?" Applied as a penalty rather than
#: a multiplier so the breakdown stays additive and readable.
CONFIDENCE_PENALTY: Mapping[str, float] = {
    "high": 0.0,
    "medium": 10.0,
    "low": 25.0,
    "unknown": 40.0,
}

#: A fact we could not read is not a fact. This is the numeric expression
#: of the UNKNOWN discipline: a path resting on undetermined evidence
#: scores materially lower than one resting on observed evidence.
INCOMPLETENESS_PENALTY = 20.0

# ---------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------
#
# No prior attack-path threshold exists anywhere in this repository (see
# the current-state audit §4), so there is no existing contract to
# preserve and these are new. They use the project's four-value
# ``Severity`` — no fifth value, no parallel enum.

SEVERITY_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (70.0, Severity.CRITICAL),
    (40.0, Severity.HIGH),
    (20.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """A score and the named contributions that produced it.

    Exists so the number can be defended. ``factors`` maps a human-
    readable reason to its numeric contribution; negatives are penalties.
    """

    value: float
    severity: Severity
    model_version: str = SCORING_MODEL_VERSION
    factors: Mapping[str, float] = field(default_factory=dict)

    def explain(self) -> tuple[str, ...]:
        """The breakdown as sorted lines, largest contribution first."""

        return tuple(
            f"{name}: {contribution:+.1f}"
            for name, contribution in sorted(
                self.factors.items(), key=lambda kv: (-abs(kv[1]), kv[0])
            )
        )


def severity_for(score: float) -> Severity:
    """Map a 0-100 score onto the project's existing ``Severity``."""

    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.LOW  # pragma: no cover - the 0.0 row already catches this


def score_path(
    *,
    has_internet_edge: bool,
    exposure_attributes: tuple[str, ...],
    unrestricted_ingress: bool,
    privilege_attributes: tuple[str, ...],
    target_sensitivity: str | None,
    relationship_types: tuple[str, ...],
    hop_count: int,
    confidence: str,
    evidence_incomplete: bool,
    blocked: bool,
) -> ScoreBreakdown:
    """Compute a path's risk, deterministically.

    ``blocked`` short-circuits to zero. That is not a scoring choice — it
    is the ``AttackPath`` aggregate's own invariant (a blocked path must
    score 0), enforced here so the two can never disagree.
    """

    factors: dict[str, float] = {}

    if blocked:
        return ScoreBreakdown(
            value=0.0,
            severity=Severity.LOW,
            factors={"blocked_edge_on_path": 0.0},
        )

    # --- Exposure. Edge and attribute evidence are alternatives, not
    # cumulative: they are two ways of learning the same fact, and adding
    # both would double-count internet reachability.
    if has_internet_edge:
        factors["internet_reachable_via_graph_edge"] = EXPOSURE_DIRECT_INTERNET_EDGE
    elif exposure_attributes:
        factors[f"publicly_exposed_by_attribute({','.join(exposure_attributes)})"] = (
            EXPOSURE_ATTRIBUTE_EVIDENCE
        )
    if unrestricted_ingress:
        factors["network_control_allows_unrestricted_ingress"] = EXPOSURE_UNRESTRICTED_INGRESS

    # --- Privilege, capped: two routes to total control is still total
    # control, and letting them stack would rank an admin role with an
    # escalation path above the ceiling for no added real risk.
    privilege = 0.0
    if "has_administrator_access" in privilege_attributes:
        privilege += PRIVILEGE_ADMINISTRATOR
    if (
        "has_privilege_escalation_path" in privilege_attributes
        or "has_pass_role_escalation" in privilege_attributes
    ):
        privilege += PRIVILEGE_ESCALATION_PATH
    if "has_wildcard_action" in privilege_attributes:
        privilege += PRIVILEGE_WILDCARD_ACTION
    if privilege:
        factors[f"privileged_identity({','.join(sorted(privilege_attributes))})"] = min(
            privilege, PRIVILEGE_CAP
        )

    # --- Target sensitivity.
    sensitivity = {
        "secrets": SENSITIVITY_SECRETS,
        "storage": SENSITIVITY_STORAGE,
        "identity": SENSITIVITY_IDENTITY,
        "audit_log": SENSITIVITY_AUDIT_LOG,
    }.get(target_sensitivity or "")
    if sensitivity:
        factors[f"sensitive_target({target_sensitivity})"] = sensitivity

    # --- Dangerous relationships on the path.
    if "assumes" in relationship_types:
        factors["traverses_assumes_relationship"] = RELATIONSHIP_ASSUMES
    elif "accesses" in relationship_types:
        factors["traverses_accesses_relationship"] = RELATIONSHIP_ACCESSES

    # --- Length discount.
    extra_hops = max(0, hop_count - 1)
    if extra_hops:
        factors["path_length_discount"] = -min(
            extra_hops * LENGTH_DISCOUNT_PER_HOP, LENGTH_DISCOUNT_MAX
        )

    # --- Penalties.
    penalty = CONFIDENCE_PENALTY.get(confidence, CONFIDENCE_PENALTY["unknown"])
    if penalty:
        factors[f"confidence_penalty({confidence})"] = -penalty
    if evidence_incomplete:
        factors["incomplete_evidence_penalty"] = -INCOMPLETENESS_PENALTY

    total = max(0.0, min(100.0, sum(factors.values())))
    return ScoreBreakdown(
        value=round(total, 2), severity=severity_for(total), factors=factors
    )


__all__ = [
    "CONFIDENCE_PENALTY",
    "INCOMPLETENESS_PENALTY",
    "SCORING_MODEL_VERSION",
    "SEVERITY_THRESHOLDS",
    "ScoreBreakdown",
    "score_path",
    "severity_for",
]
