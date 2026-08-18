from __future__ import annotations

from infrastructure.errors import InfrastructureError


class RuleCatalogError(InfrastructureError):
    """The rule catalog could not be loaded — malformed YAML, a missing
    required field, or a value that doesn't match the Domain's ``Rule``
    contract (e.g. an unknown ``severity``). Always identifies the
    offending file.
    """
