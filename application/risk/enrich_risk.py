"""``EnrichRisk`` (blueprint §4).

KNOWN LIMITATION — read before extending this file: the blueprint gives
the exact CRSF-1.1 *weights* (§13) but nowhere specifies how a raw
signal (a ``Severity``, "is this resource publicly exposed", an
environment label, a ``ConfidenceScore``, attack path involvement) maps
to the ``[0, 100]`` factor scores ``RiskScore.calculate`` expects. That
mapping is real business logic the blueprint does not define — Phase 1
already flagged this as an open point, and this phase does not invent
it either. ``EnrichRisk`` is therefore a pure, honest wrapper: it takes
already-computed factors and applies the Domain formula, nothing more.
Deriving those factors from a ``Finding``/``ResourceGraph`` is left for
whichever phase receives an authoritative specification of that mapping
(see docs/architecture/phase-2-application.md, Known Limitations).
"""

from __future__ import annotations

from dataclasses import dataclass

from domain.risk.models import RiskScore


@dataclass(frozen=True, slots=True)
class RiskFactors:
    """The five pre-computed ``[0, 100]`` factors ``RiskScore.calculate``
    requires. Validation of the bounds happens in the Domain call itself
    (``RiskScore.calculate``) — this is a plain carrier, not a second
    validation layer.
    """

    severity_factor: float
    exposure_factor: float
    environment_factor: float
    confidence_factor: float
    attack_path_involvement_factor: float


class EnrichRisk:
    """Applies the CRSF-1.1 formula to pre-computed factors. Does not,
    and cannot, derive those factors itself — see module docstring.
    """

    def enrich(self, factors: RiskFactors) -> RiskScore:
        return RiskScore.calculate(
            severity_factor=factors.severity_factor,
            exposure_factor=factors.exposure_factor,
            environment_factor=factors.environment_factor,
            confidence_factor=factors.confidence_factor,
            attack_path_involvement_factor=factors.attack_path_involvement_factor,
        )
