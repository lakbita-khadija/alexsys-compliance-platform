"""``LoadRuleCatalog`` (blueprint §4).

An abstraction over obtaining the current ``Rule`` catalog. Concretely
loading rules from YAML is explicitly an infrastructure concern
(blueprint §5: "rules/ yaml loader") — this port exists so
``EvaluateRules`` can depend on "some way to get rules" without knowing
how they're stored, per the dependency direction in §3 of the blueprint
(``application → domain`` only, never a concrete loader).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from domain.rules.rule import Rule


class LoadRuleCatalog(ABC):
    """Port: obtain the set of ``Rule``s to evaluate."""

    @abstractmethod
    def load(self) -> tuple[Rule, ...]:
        """Return the current rule catalog."""
