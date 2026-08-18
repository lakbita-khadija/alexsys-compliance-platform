"""``CompositeRuleCatalog`` — one ``LoadRuleCatalog`` composed of several.

A multi-cloud engine keeps one rule catalog per provider
(``rules/aws/``, ``rules/azure/``) so each stays independently
readable, reviewable, and versionable. A scan, though, wants a single
catalog. This composes them without either provider's loader knowing
the other exists.

It is an Application-layer concern (not Infrastructure) because it
composes the PORT, not any particular storage format: the delegates
happen to be ``YamlRuleCatalog``s today, but a database-backed or
API-backed catalog would compose identically.

Rule ids must be globally unique across the composed catalogs. A
collision is raised rather than silently resolved by ordering — two
rules sharing an id would make ``Finding.rule_id`` ambiguous and, worse,
make the conformance framework's expectations non-deterministic.
"""

from __future__ import annotations

from application.errors import ApplicationError
from application.rules.rule_catalog import LoadRuleCatalog
from domain.rules.rule import Rule
from domain.shared.identifiers import RuleId


class DuplicateRuleIdError(ApplicationError):
    """Two composed catalogs declare the same ``RuleId``."""


class CompositeRuleCatalog(LoadRuleCatalog):
    """Presents several ``LoadRuleCatalog``s as one.

    Load order is the order the delegates were given, and each
    delegate's own order is preserved — so the composed catalog is as
    deterministic as its parts.
    """

    def __init__(self, *catalogs: LoadRuleCatalog) -> None:
        self._catalogs = catalogs

    def load(self) -> tuple[Rule, ...]:
        rules: list[Rule] = []
        seen: dict[RuleId, Rule] = {}

        for catalog in self._catalogs:
            for rule in catalog.load():
                if rule.id in seen:
                    raise DuplicateRuleIdError(
                        f"duplicate rule id {rule.id!s} across composed catalogs — rule ids must be "
                        "globally unique so Finding.rule_id is unambiguous"
                    )
                seen[rule.id] = rule
                rules.append(rule)

        return tuple(rules)
