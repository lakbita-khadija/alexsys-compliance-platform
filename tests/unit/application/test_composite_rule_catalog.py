import pytest

from application.rules.composite_rule_catalog import CompositeRuleCatalog, DuplicateRuleIdError
from application.rules.rule_catalog import LoadRuleCatalog
from domain.rules.rule import Rule
from domain.shared.enums import Severity
from domain.shared.identifiers import RuleId


class FakeCatalog(LoadRuleCatalog):
    def __init__(self, rules):
        self._rules = tuple(rules)

    def load(self):
        return self._rules


def make_rule(rule_id: str, resource_type: str | None = None) -> Rule:
    return Rule(
        id=RuleId(rule_id),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        severity=Severity.HIGH,
        condition={"field": "public", "operator": "equals", "value": True},
        applies_to_resource_type=resource_type,
    )


class TestCompositeRuleCatalog:
    def test_combines_rules_from_every_catalog(self) -> None:
        aws = FakeCatalog([make_rule("s3-public"), make_rule("kms-rotation")])
        azure = FakeCatalog([make_rule("azure-storage-public")])
        rules = CompositeRuleCatalog(aws, azure).load()
        assert {str(r.id) for r in rules} == {"s3-public", "kms-rotation", "azure-storage-public"}

    def test_preserves_delegate_order(self) -> None:
        first = FakeCatalog([make_rule("a"), make_rule("b")])
        second = FakeCatalog([make_rule("c")])
        rules = CompositeRuleCatalog(first, second).load()
        assert [str(r.id) for r in rules] == ["a", "b", "c"]

    def test_empty_composition_is_empty(self) -> None:
        assert CompositeRuleCatalog().load() == ()

    def test_composing_empty_catalogs_is_empty(self) -> None:
        assert CompositeRuleCatalog(FakeCatalog([]), FakeCatalog([])).load() == ()

    def test_single_catalog_passes_through_unchanged(self) -> None:
        aws = FakeCatalog([make_rule("s3-public")])
        assert CompositeRuleCatalog(aws).load() == aws.load()

    def test_duplicate_rule_id_across_catalogs_is_rejected(self) -> None:
        aws = FakeCatalog([make_rule("shared-id")])
        azure = FakeCatalog([make_rule("shared-id")])
        with pytest.raises(DuplicateRuleIdError, match="shared-id"):
            CompositeRuleCatalog(aws, azure).load()

    def test_duplicate_within_a_single_catalog_is_also_rejected(self) -> None:
        catalog = FakeCatalog([make_rule("dup"), make_rule("dup")])
        with pytest.raises(DuplicateRuleIdError):
            CompositeRuleCatalog(catalog).load()

    def test_composition_is_deterministic(self) -> None:
        aws = FakeCatalog([make_rule("a"), make_rule("b")])
        azure = FakeCatalog([make_rule("c")])
        composite = CompositeRuleCatalog(aws, azure)
        assert composite.load() == composite.load()

    def test_composite_satisfies_the_load_rule_catalog_port(self) -> None:
        assert isinstance(CompositeRuleCatalog(), LoadRuleCatalog)


class TestRealMultiCloudCatalogsCompose:
    def test_aws_and_azure_catalogs_have_no_id_collisions(self) -> None:
        from pathlib import Path

        from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

        repo_root = Path(__file__).resolve().parents[3]
        composite = CompositeRuleCatalog(
            YamlRuleCatalog(repo_root / "rules" / "aws"),
            YamlRuleCatalog(repo_root / "rules" / "azure"),
        )
        rules = composite.load()  # raises DuplicateRuleIdError on collision
        assert len(rules) > 50

    def test_every_shipped_rule_declares_the_resource_type_it_applies_to(self) -> None:
        from pathlib import Path

        from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

        repo_root = Path(__file__).resolve().parents[3]
        composite = CompositeRuleCatalog(
            YamlRuleCatalog(repo_root / "rules" / "aws"),
            YamlRuleCatalog(repo_root / "rules" / "azure"),
        )
        unscoped = [str(r.id) for r in composite.load() if r.applies_to_resource_type is None]
        assert not unscoped, (
            "every shipped rule must declare applies_to_resource_type — an unscoped rule "
            f"fires against every resource type in every provider: {unscoped}"
        )
