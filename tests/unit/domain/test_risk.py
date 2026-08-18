import pytest

from domain.risk.models import ConfidenceScore, RiskScore
from domain.shared.errors import InvalidScoreValue


class TestRiskScoreBoundaries:
    def test_valid_boundary_values(self) -> None:
        assert RiskScore(value=0).value == 0
        assert RiskScore(value=100).value == 100

    @pytest.mark.parametrize("bad_value", [-0.01, 100.01, -50, 200])
    def test_out_of_bounds_value_is_rejected(self, bad_value) -> None:
        with pytest.raises(InvalidScoreValue):
            RiskScore(value=bad_value)

    def test_default_model_version_is_crsf_1_1(self) -> None:
        assert RiskScore(value=50).model_version == "crsf-1.1"

    def test_risk_score_is_immutable(self) -> None:
        score = RiskScore(value=50)
        with pytest.raises(Exception):
            score.value = 10  # type: ignore[misc]


class TestConfidenceScoreBoundaries:
    def test_valid_boundary_values(self) -> None:
        assert ConfidenceScore(value=0).value == 0
        assert ConfidenceScore(value=100).value == 100

    @pytest.mark.parametrize("bad_value", [-1, 101])
    def test_out_of_bounds_value_is_rejected(self, bad_value) -> None:
        with pytest.raises(InvalidScoreValue):
            ConfidenceScore(value=bad_value)


class TestCrsf11Formula:
    """Exact formula from blueprint §13:
    severity 40% + exposure 25% + environment 10% + confidence 10%
    + attack_path_involvement 15%, model_version="crsf-1.1".
    """

    def test_all_factors_at_maximum_yields_maximum_score(self) -> None:
        score = RiskScore.calculate(
            severity_factor=100,
            exposure_factor=100,
            environment_factor=100,
            confidence_factor=100,
            attack_path_involvement_factor=100,
        )
        assert score.value == 100
        assert score.model_version == "crsf-1.1"

    def test_all_factors_at_minimum_yields_minimum_score(self) -> None:
        score = RiskScore.calculate(
            severity_factor=0,
            exposure_factor=0,
            environment_factor=0,
            confidence_factor=0,
            attack_path_involvement_factor=0,
        )
        assert score.value == 0

    def test_weighted_combination_matches_blueprint_formula_exactly(self) -> None:
        # 0.40*80 + 0.25*50 + 0.10*20 + 0.10*90 + 0.15*0 = 32+12.5+2+9+0 = 55.5
        score = RiskScore.calculate(
            severity_factor=80,
            exposure_factor=50,
            environment_factor=20,
            confidence_factor=90,
            attack_path_involvement_factor=0,
        )
        assert score.value == pytest.approx(55.5)

    def test_severity_weight_is_forty_percent_in_isolation(self) -> None:
        # every other factor at 0 isolates the severity weight
        score = RiskScore.calculate(
            severity_factor=100,
            exposure_factor=0,
            environment_factor=0,
            confidence_factor=0,
            attack_path_involvement_factor=0,
        )
        assert score.value == pytest.approx(40.0)

    def test_attack_path_involvement_weight_is_fifteen_percent_in_isolation(self) -> None:
        score = RiskScore.calculate(
            severity_factor=0,
            exposure_factor=0,
            environment_factor=0,
            confidence_factor=0,
            attack_path_involvement_factor=100,
        )
        assert score.value == pytest.approx(15.0)

    def test_calculate_rejects_out_of_bounds_factor(self) -> None:
        with pytest.raises(InvalidScoreValue):
            RiskScore.calculate(
                severity_factor=150,
                exposure_factor=0,
                environment_factor=0,
                confidence_factor=0,
                attack_path_involvement_factor=0,
            )

    def test_calculate_is_deterministic(self) -> None:
        inputs = dict(
            severity_factor=63,
            exposure_factor=41,
            environment_factor=77,
            confidence_factor=12,
            attack_path_involvement_factor=8,
        )
        results = {RiskScore.calculate(**inputs).value for _ in range(20)}
        assert len(results) == 1
