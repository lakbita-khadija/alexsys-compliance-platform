"""The conformance suite proper: every scenario in
``tests/conformance/scenarios/`` run against the REAL rule catalog in
``rules/aws/`` (Phase 3B design proposal, Parts K/L/M).

This suite needs no AWS credentials and no deployed Terraform — the
scenarios are synthetic resource shapes (see
``infrastructure/conformance/scenario_loader.py``'s docstring for why),
so it runs in CI, deterministically, in milliseconds. It validates the
RULE CATALOG's behavior; validating the AWS COLLECTOR against a real
account is the separate, opt-in ``tests/integration/aws`` suite.

``TestComparatorActuallyDetectsFaults`` at the bottom is the meta-test
Part M asks for: it deliberately corrupts a scenario's expectations and
asserts the comparator reports the fault. Without it, a comparator that
returned PASS unconditionally would make every test above pass too.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from application.conformance.models import ConformanceOutcome, ExpectedFinding, Scenario
from application.conformance.report import all_fully_conformant, render_summary
from application.conformance.runner import RunConformanceScenario
from application.rules.composite_rule_catalog import CompositeRuleCatalog
from application.rules.rule_catalog import LoadRuleCatalog
from domain.findings.models import FindingStatus
from domain.shared.enums import Severity
from domain.shared.identifiers import RuleId
from infrastructure.conformance.scenario_loader import YamlScenarioLoader
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

_REPO_ROOT = Path(__file__).resolve().parents[2]
AWS_RULES_DIR = _REPO_ROOT / "rules" / "aws"
AZURE_RULES_DIR = _REPO_ROOT / "rules" / "azure"
SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


class CachingRuleCatalog(LoadRuleCatalog):
    """Loads the real ``YamlRuleCatalog`` exactly once.

    ``EvaluateRules.evaluate()`` calls ``load()`` on every invocation
    (correct for production: a catalog on disk can change between
    scans). Across ~37 scenarios × several test methods that means
    re-parsing every rule YAML hundreds of times, which dominated this
    suite's runtime. Caching belongs here in the test fixture, not in
    the production loader — the rules genuinely cannot change during
    one test session.
    """

    def __init__(self, delegate: LoadRuleCatalog) -> None:
        self._rules = delegate.load()

    def load(self):
        return self._rules


@pytest.fixture(scope="module")
def scenarios() -> tuple[Scenario, ...]:
    return YamlScenarioLoader(SCENARIOS_DIR).load()


@pytest.fixture(scope="module")
def runner() -> RunConformanceScenario:
    # BOTH provider catalogs, composed — so every scenario runs against
    # the complete multi-cloud rule set. This is what proves the AWS and
    # Azure catalogs coexist without interfering: an Azure rule firing
    # against an AWS resource (or vice versa) would surface here as an
    # UNEXPECTED_FINDING.
    return RunConformanceScenario(
        CachingRuleCatalog(
            CompositeRuleCatalog(YamlRuleCatalog(AWS_RULES_DIR), YamlRuleCatalog(AZURE_RULES_DIR))
        )
    )


def _scenario_ids(scenarios: tuple[Scenario, ...]) -> list[str]:
    return [s.scenario_id for s in scenarios]


class TestScenariosLoad:
    def test_scenarios_are_discovered(self, scenarios) -> None:
        assert len(scenarios) >= 30, "the conformance suite should cover every rule domain"

    def test_scenario_ids_are_unique(self, scenarios) -> None:
        ids = _scenario_ids(scenarios)
        assert len(ids) == len(set(ids))

    def test_every_rule_domain_is_covered(self, scenarios) -> None:
        prefixes = {s.scenario_id.split("-")[0] for s in scenarios}
        assert {"s3", "sg", "ec2", "iam", "kms", "cloudtrail"} <= prefixes

    def test_relationship_scenarios_build_a_real_graph(self, scenarios) -> None:
        with_graph = [s for s in scenarios if s.graph is not None]
        assert with_graph, "at least some scenarios must exercise cross-resource rules"
        for scenario in with_graph:
            assert scenario.resources_by_id, "a graph scenario must supply its neighbors' full resources"


class TestEveryScenarioIsConformant:
    """The suite's core assertion: the real rule catalog behaves exactly
    as every scenario declares it should.
    """

    def test_every_scenario_is_fully_conformant(self, scenarios, runner) -> None:
        reports = tuple(runner.run(scenario) for scenario in scenarios)
        if not all_fully_conformant(reports):
            pytest.fail("rule catalog does not conform to its scenarios:\n" + render_summary(reports))

    def test_no_scenario_produces_zero_assertions(self, scenarios, runner) -> None:
        for scenario in scenarios:
            report = runner.run(scenario)
            assert report.results, f"{scenario.scenario_id} produced no comparisons at all"

    def test_conformance_run_is_deterministic(self, scenarios, runner) -> None:
        first = tuple(runner.run(s) for s in scenarios)
        second = tuple(runner.run(s) for s in scenarios)
        assert [r.results for r in first] == [r.results for r in second]


class TestThreeValuedLogicIsPreservedEndToEnd:
    def test_indeterminate_expectations_are_actually_exercised(self, scenarios, runner) -> None:
        # Guards against the conformance suite silently losing its
        # INDETERMINATE coverage: if every scenario only ever asserted
        # PASS/FAIL, the "no hidden compliance" invariant would go
        # untested here even while every test still passed.
        indeterminate_expectations = [
            (s.scenario_id, e.rule_id)
            for s in scenarios
            for e in s.expected_findings
            if e.status is FindingStatus.INDETERMINATE
        ]
        assert indeterminate_expectations, "the suite must cover INDETERMINATE outcomes"

    def test_no_finding_status_falls_outside_the_three_values(self, scenarios, runner) -> None:
        for scenario in scenarios:
            report = runner.run(scenario)
            for result in report.results:
                if result.actual is not None:
                    assert result.actual.status in (
                        FindingStatus.PASS,
                        FindingStatus.FAIL,
                        FindingStatus.INDETERMINATE,
                    )


class TestComparatorActuallyDetectsFaults:
    """META-TEST (Part M). Everything above asserts "the catalog
    conforms." That is only meaningful if non-conformance would
    actually be *caught* — a comparator hard-wired to return PASS would
    satisfy every test above. These tests corrupt a known-good scenario
    and assert the specific fault is reported.
    """

    @pytest.fixture
    def good_scenario(self, scenarios) -> Scenario:
        return next(s for s in scenarios if s.scenario_id == "s3-acl-public-bucket")

    def test_flipping_an_expected_status_is_reported_as_false_positive(self, good_scenario, runner) -> None:
        # The rule genuinely FAILs; asserting it should PASS must be
        # classified as a false positive, not silently accepted.
        corrupted = replace(
            good_scenario,
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-bucket-public"), status=FindingStatus.PASS),),
        )
        report = runner.run(corrupted)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("s3-bucket-public")] is ConformanceOutcome.FALSE_POSITIVE
        assert report.is_fully_conformant is False

    def test_expecting_a_nonexistent_rule_is_reported_as_missing_finding(self, good_scenario, runner) -> None:
        corrupted = replace(
            good_scenario,
            expected_findings=(ExpectedFinding(rule_id=RuleId("no-such-rule"), status=FindingStatus.FAIL),),
        )
        report = runner.run(corrupted)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("no-such-rule")] is ConformanceOutcome.MISSING_FINDING

    def test_wrong_severity_is_reported(self, good_scenario, runner) -> None:
        corrupted = replace(
            good_scenario,
            expected_findings=(
                ExpectedFinding(rule_id=RuleId("s3-bucket-public"), status=FindingStatus.FAIL, severity=Severity.LOW),
            ),
        )
        report = runner.run(corrupted)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("s3-bucket-public")] is ConformanceOutcome.WRONG_SEVERITY

    def test_wrong_evidence_is_reported(self, good_scenario, runner) -> None:
        corrupted = replace(
            good_scenario,
            expected_findings=(
                ExpectedFinding(
                    rule_id=RuleId("s3-bucket-public"),
                    status=FindingStatus.FAIL,
                    evidence_contains=("this text is definitely not in the evidence",),
                ),
            ),
        )
        report = runner.run(corrupted)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("s3-bucket-public")] is ConformanceOutcome.WRONG_EVIDENCE

    def test_dropping_an_expectation_surfaces_an_unexpected_finding(self, good_scenario, runner) -> None:
        # Keep only one expectation; the other genuinely-failing rules
        # must then surface as UNEXPECTED_FINDING rather than vanishing.
        corrupted = replace(
            good_scenario,
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-bucket-public"), status=FindingStatus.FAIL),),
        )
        report = runner.run(corrupted)
        unexpected = [r for r in report.results if r.outcome is ConformanceOutcome.UNEXPECTED_FINDING]
        assert unexpected, "silently dropping an expectation must not make a real failing rule disappear"

    def test_a_false_negative_would_be_caught(self, scenarios, runner) -> None:
        # Mirror image of the false-positive test: assert FAIL on a rule
        # that genuinely PASSes for this resource.
        compliant = next(s for s in scenarios if s.scenario_id == "s3-fully-compliant-bucket")
        corrupted = replace(
            compliant,
            expected_findings=(ExpectedFinding(rule_id=RuleId("s3-bucket-public"), status=FindingStatus.FAIL),),
        )
        report = runner.run(corrupted)
        outcomes = {r.rule_id: r.outcome for r in report.results}
        assert outcomes[RuleId("s3-bucket-public")] is ConformanceOutcome.FALSE_NEGATIVE


class TestConformanceFrameworkDoesNotEvaluateRules:
    """Architectural guard (Part R): the comparator must never contain
    rule-evaluation logic of its own — it compares, the Rule Engine
    decides.

    These assert against the module's parsed AST rather than its raw
    source text, because the comparator's own docstring legitimately
    *names* ``evaluate_condition`` in order to state that it never calls
    it. A raw substring check would flag that documentation as a
    violation — testing the prose instead of the code.
    """

    @staticmethod
    def _imported_names(module) -> set[str]:
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(module))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module)
                names.update(f"{node.module}.{alias.name}" for alias in node.names)
        return names

    @staticmethod
    def _called_names(module) -> set[str]:
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(module))
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        return called

    def test_comparator_does_not_import_the_rule_evaluator(self) -> None:
        import application.conformance.comparator as comparator_module

        imported = self._imported_names(comparator_module)
        assert not any("domain.rules.conditions" in name for name in imported)
        assert not any("evaluate_rules" in name for name in imported)

    def test_comparator_never_calls_a_rule_evaluation_function(self) -> None:
        import application.conformance.comparator as comparator_module

        called = self._called_names(comparator_module)
        assert "evaluate_condition" not in called
        assert "evaluate" not in called

    def test_comparator_does_not_parse_terraform(self) -> None:
        import inspect

        import application.conformance.comparator as comparator_module

        imported = self._imported_names(comparator_module)
        assert not any("hcl" in name or "terraform" in name for name in imported)
        # `tfstate` has no legitimate reason to appear anywhere in this
        # module, docstring included — unlike `evaluate_condition`.
        assert "tfstate" not in inspect.getsource(comparator_module).lower()


class TestScenariosAreSeparateFromTerraform:
    def test_scenario_files_contain_no_terraform_references(self) -> None:
        for path in sorted(SCENARIOS_DIR.glob("*.yaml")):
            text = path.read_text().lower()
            assert "tfstate" not in text
            assert "resource \"aws_" not in text

    def test_terraform_contains_no_rule_engine_metadata(self) -> None:
        terraform_dir = _REPO_ROOT / "terraform"
        forbidden = ("expected_rule_id", "expected_finding", "rule_id", "logical_finding_id")
        for path in sorted(terraform_dir.rglob("*.tf")):
            text = path.read_text()
            for token in forbidden:
                assert token not in text, f"{path} leaks Rule Engine metadata: {token}"
