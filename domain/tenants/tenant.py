"""The Tenant entity — the domain-level anchor for tenant isolation.

Blueprint §3/§10 note that isolation is today enforced only inside
``ResourceGraph``/rule evaluation, with no ``Tenant`` entity. This module
formalizes that concept so tenant identity is a first-class domain
citizen, not an incidental string.
"""

from __future__ import annotations

from dataclasses import dataclass

from domain.shared.errors import DomainError
from domain.shared.identifiers import TenantId


class InvalidTenant(DomainError):
    """A ``Tenant`` was constructed with invalid data."""


@dataclass(frozen=True, slots=True)
class Tenant:
    """A tenant boundary. Every resource, finding, graph, and attack path
    in the Domain is scoped to exactly one ``Tenant``.
    """

    id: TenantId
    name: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise InvalidTenant("Tenant.name must be a non-blank string")
