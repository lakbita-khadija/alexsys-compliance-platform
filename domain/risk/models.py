"""Risk domain concepts (blueprint §13).

Three distinct scores answer three distinct questions and must never be
collapsed into one:

* ``Severity`` (``domain.shared.enums``) — "how serious is this rule
  violation, in the abstract?" Static, defined by the rule itself.
* ``RiskScore`` — "how risky is this finding, in this actual context?"
  Contextual, 0-100, computed from the exact weighted formula specified
  in blueprint §13 (``model_version="crsf-1.1"``): severity 40% +
  exposure 25% + environment 10% + confidence 10% +
  attack_path_involvement 15%.
* ``ConfidenceScore`` — "how much can we trust the data this was computed
  from?" A property of the collection itself, not of the risk.

IMPORTANT — deliberately NOT implemented here: the blueprint specifies
the *weights* combining five 0-100 factors, but nowhere specifies how a
raw signal (e.g. a ``Severity`` enum member, or "is this resource
publicly exposed") maps to a 0-100 factor score. Inventing that mapping
would be inventing business logic the blueprint does not define.
``RiskScore.calculate`` therefore accepts five already-computed 0-100
factor scores — deriving those factors from a ``Finding``/``ResourceGraph``
is an explicit open point for a later phase (see
docs/architecture/phase-1-domain.md, Known Limitations).
"""

from __future__ import annotations

from dataclasses import dataclass

from domain.shared.errors import InvalidScoreValue

CRSF_MODEL_VERSION = "crsf-1.1"

_SEVERITY_WEIGHT = 0.40
_EXPOSURE_WEIGHT = 0.25
_ENVIRONMENT_WEIGHT = 0.10
_CONFIDENCE_WEIGHT = 0.10
_ATTACK_PATH_INVOLVEMENT_WEIGHT = 0.15


def _validate_bounded(name: str, value: float) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not (0 <= value <= 100):
        raise InvalidScoreValue(f"{name} must be between 0 and 100, got {value!r}")


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A contextual risk score in ``[0, 100]``, tied to the model version
    that produced it so future factors can be added (as they were, from
    ``crsf-1.0`` to ``crsf-1.1``, per blueprint §13) without silently
    reinterpreting historical scores.
    """

    value: float
    model_version: str = CRSF_MODEL_VERSION

    def __post_init__(self) -> None:
        _validate_bounded("RiskScore.value", self.value)

    @classmethod
    def calculate(
        cls,
        *,
        severity_factor: float,
        exposure_factor: float,
        environment_factor: float,
        confidence_factor: float,
        attack_path_involvement_factor: float,
    ) -> "RiskScore":
        """Apply the exact CRSF-1.1 weighted formula from blueprint §13 to
        five pre-computed 0-100 factor scores.
        """

        factors = {
            "severity_factor": severity_factor,
            "exposure_factor": exposure_factor,
            "environment_factor": environment_factor,
            "confidence_factor": confidence_factor,
            "attack_path_involvement_factor": attack_path_involvement_factor,
        }
        for name, value in factors.items():
            _validate_bounded(name, value)

        weighted_sum = (
            severity_factor * _SEVERITY_WEIGHT
            + exposure_factor * _EXPOSURE_WEIGHT
            + environment_factor * _ENVIRONMENT_WEIGHT
            + confidence_factor * _CONFIDENCE_WEIGHT
            + attack_path_involvement_factor * _ATTACK_PATH_INVOLVEMENT_WEIGHT
        )
        return cls(value=round(weighted_sum, 2))


@dataclass(frozen=True, slots=True)
class ConfidenceScore:
    """How reliable the collected information behind a finding is, in
    ``[0, 100]`` — independent of both ``Severity`` and ``RiskScore``.
    """

    value: float

    def __post_init__(self) -> None:
        _validate_bounded("ConfidenceScore.value", self.value)
