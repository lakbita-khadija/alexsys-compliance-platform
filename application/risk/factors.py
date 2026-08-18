"""Deriving the five CRSF-1.1 risk factors from real scan data.

## Why this file did not exist before

``RiskScore.calculate`` needs five ``[0, 100]`` factors. The blueprint
specifies the **weights** that combine them (§13) and never specifies how
a raw signal becomes a factor. Phases 1 and 2 refused to invent that
mapping and left ``EnrichRisk`` uncalled — a defensible choice, and one
that had a hard blocker underneath it: ``attack_path_involvement`` was
underivable by construction, because the analyzer that would supply it
returned nothing.

That blocker is gone. This module supplies the mapping.

## What kind of thing this is

**A documented product judgement, not a blueprint-specified formula.**
The distinction matters enough to state twice: the *weights* come from
the blueprint and are authoritative; the *factor derivations* below are
decisions made here, versioned separately so they can be revised without
anyone believing they were handed down.

Every derivation is a small explicit table. None of them infers anything
it was not told.

## The environment problem, stated rather than hidden

``Finding.environment`` is optional and, in practice, almost always
``None`` — no collector populates it, because nothing maps cloud tags to
an environment taxonomy yet. A factor cannot be omitted, so unknown
environment resolves to ``UNKNOWN_ENVIRONMENT_FACTOR``, a deliberately
mid-scale value, and the enrichment records that it was defaulted.
Scoring every finding as if it were production would inflate the whole
estate; scoring them as if they were sandbox would hide real risk.
Neither is honest, so the assumption is made visible instead.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from application.risk.enrich_risk import RiskFactors
from domain.attack_paths.models import AttackPath
from domain.findings.models import Finding
from domain.shared.enums import Severity

#: Versioned independently of ``crsf-1.1``: the weights are the
#: blueprint's, these derivations are ours, and conflating the two would
#: make it impossible to tell which one changed a historical score.
FACTOR_MODEL_VERSION = "rfd-1.0"

#: Severity is already a four-value ordinal scale. Spreading it across
#: the full range rather than clustering it keeps the 40% severity weight
#: meaningful.
SEVERITY_FACTOR: Mapping[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 75.0,
    Severity.MEDIUM: 45.0,
    Severity.LOW: 20.0,
}

#: See the module docstring. Mid-scale, and always reported as defaulted.
UNKNOWN_ENVIRONMENT_FACTOR = 50.0

#: Environment labels this codebase can actually receive today. Anything
#: else falls back to the unknown value rather than being guessed at.
ENVIRONMENT_FACTOR: Mapping[str, float] = {
    "production": 100.0,
    "prod": 100.0,
    "staging": 60.0,
    "development": 30.0,
    "dev": 30.0,
    "sandbox": 15.0,
    "test": 15.0,
}

#: Graph confidence, carried through to the risk factor. Note the
#: direction: HIGH confidence means a HIGH factor, because CRSF-1.1 adds
#: the confidence factor rather than discounting by it — a finding we are
#: sure about is riskier than one we are guessing at.
CONFIDENCE_FACTOR: Mapping[str, float] = {
    "high": 100.0,
    "medium": 65.0,
    "low": 35.0,
    "unknown": 20.0,
}

#: A finding on no attack path contributes zero involvement. This is the
#: one factor that genuinely required the analyzer.
NO_ATTACK_PATH_FACTOR = 0.0


def severity_factor(severity: Severity) -> float:
    return SEVERITY_FACTOR[severity]


def environment_factor(environment: str | None) -> tuple[float, bool]:
    """``(factor, was_defaulted)``.

    The second element is not decoration — it is what lets the enrichment
    tell a reader "this risk assumed an unknown environment" instead of
    presenting a guess as a measurement.
    """

    if environment is None:
        return UNKNOWN_ENVIRONMENT_FACTOR, True
    resolved = ENVIRONMENT_FACTOR.get(environment.strip().lower())
    if resolved is None:
        return UNKNOWN_ENVIRONMENT_FACTOR, True
    return resolved, False


def confidence_factor(finding: Finding, paths: Sequence[AttackPath]) -> float:
    """Weakest confidence among the paths a finding sits on.

    With no path, the finding's own evidence quality is the best signal
    available: a finding carrying indeterminate related resources was
    built on data we could not fully read.
    """

    if paths:
        return min(
            CONFIDENCE_FACTOR.get(path.confidence, CONFIDENCE_FACTOR["unknown"])
            for path in paths
        )
    if finding.indeterminate_resources:
        return CONFIDENCE_FACTOR["low"]
    return CONFIDENCE_FACTOR["high"]


def exposure_factor(paths: Sequence[AttackPath]) -> float:
    """How exposed this finding's resource is, per the attack paths.

    Derived from the paths' own risk scores rather than re-deriving
    exposure from the graph: the analyzer already did that work, with
    evidence, and a second independent derivation could disagree with the
    first.
    """

    if not paths:
        return 0.0
    return max(path.risk_score for path in paths)


def attack_path_involvement_factor(paths: Sequence[AttackPath]) -> float:
    """The factor that was underivable before the analyzer existed.

    Scales with how many paths implicate the resource, because a resource
    on three attack paths is genuinely worse than one on a single path,
    and saturates: past a handful, "this is badly exposed" is already
    fully expressed.
    """

    if not paths:
        return NO_ATTACK_PATH_FACTOR
    worst = max(path.risk_score for path in paths)
    multiplicity_bonus = min(len(paths) - 1, 3) * 10.0
    return min(100.0, worst + multiplicity_bonus)


def derive_factors(
    finding: Finding, paths: Sequence[AttackPath]
) -> tuple[RiskFactors, bool]:
    """``(factors, environment_was_defaulted)`` for one finding."""

    environment, defaulted = environment_factor(finding.environment)
    return (
        RiskFactors(
            severity_factor=severity_factor(finding.severity),
            exposure_factor=exposure_factor(paths),
            environment_factor=environment,
            confidence_factor=confidence_factor(finding, paths),
            attack_path_involvement_factor=attack_path_involvement_factor(paths),
        ),
        defaulted,
    )


__all__ = [
    "CONFIDENCE_FACTOR",
    "ENVIRONMENT_FACTOR",
    "FACTOR_MODEL_VERSION",
    "SEVERITY_FACTOR",
    "UNKNOWN_ENVIRONMENT_FACTOR",
    "attack_path_involvement_factor",
    "confidence_factor",
    "derive_factors",
    "environment_factor",
    "exposure_factor",
    "severity_factor",
]
