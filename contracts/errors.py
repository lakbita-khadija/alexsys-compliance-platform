"""Exceptions for the Core <-> AI Service contract boundary.

Deliberately not a subclass of ``domain.shared.errors.DomainError`` —
``contracts/`` is not the Domain, it is the translation/boundary layer
sitting outside it (blueprint §21, §26.12). A translation failure is a
boundary concern, not a business-rule violation.
"""

from __future__ import annotations


class ContractTranslationError(Exception):
    """Raised when a domain object cannot be deterministically translated
    into its external contract representation — e.g. a ``Finding`` whose
    ``framework``/``domain`` string is not one of the AI Service's closed
    vocabulary values, or whose status is ``INDETERMINATE`` (which must
    never cross this boundary).
    """
