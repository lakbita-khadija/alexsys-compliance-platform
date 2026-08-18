import pytest

from application.risk.enrich_risk import EnrichRisk, RiskFactors
from domain.risk.models import RiskScore
from domain.shared.errors import InvalidScoreValue


class TestRiskFactors:
    def test_valid_factors(self) -> None:
        factors = RiskFactors(
            severity_factor=80,
            exposure_factor=50,
            environment_factor=20,
            confidence_factor=90,
            attack_path_involvement_factor=0,
        )
        assert factors.severity_factor == 80


class TestEnrichRisk:
    def test_delegates_to_the_exact_crsf_formula(self) -> None:
        factors = RiskFactors(
            severity_factor=80,
            exposure_factor=50,
            environment_factor=20,
            confidence_factor=90,
            attack_path_involvement_factor=0,
        )
        score = EnrichRisk().enrich(factors)
        assert score == RiskScore.calculate(
            severity_factor=80,
            exposure_factor=50,
            environment_factor=20,
            confidence_factor=90,
            attack_path_involvement_factor=0,
        )

    def test_out_of_bounds_factor_is_rejected_by_the_domain(self) -> None:
        factors = RiskFactors(
            severity_factor=150,
            exposure_factor=0,
            environment_factor=0,
            confidence_factor=0,
            attack_path_involvement_factor=0,
        )
        with pytest.raises(InvalidScoreValue):
            EnrichRisk().enrich(factors)

    def test_enrichment_is_deterministic(self) -> None:
        factors = RiskFactors(
            severity_factor=63,
            exposure_factor=41,
            environment_factor=77,
            confidence_factor=12,
            attack_path_involvement_factor=8,
        )
        results = {EnrichRisk().enrich(factors) for _ in range(10)}
        assert len(results) == 1
