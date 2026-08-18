"""Application-layer exceptions.

Deliberately not a subclass of ``domain.shared.errors.DomainError`` — the
Application layer is not the Domain. Domain exceptions
(``TenantIsolationViolation``, ``GraphIntegrityViolation``,
``InvalidRuleCondition``, ...) are never caught and re-wrapped here; they
propagate to the caller unchanged, since they carry precise invariant
information a generic wrapper would destroy. This module only adds
exceptions for failure modes that are genuinely new at this layer —
currently just one: an injected port failing.
"""

from __future__ import annotations


class ApplicationError(Exception):
    """Base class for exceptions raised by the Application layer itself."""


class ResourceCollectionError(ApplicationError):
    """Raised when a ``BaseCollector`` port fails to collect resources.

    Wraps the underlying exception via ``raise ... from cause`` rather
    than swallowing it, so the original failure is still inspectable.
    """


class ConformanceError(ApplicationError):
    """Raised for a structurally invalid conformance ``Scenario`` (e.g.
    no expectations declared) — a fixture-authoring problem, distinct
    from a ``ConformanceOutcome`` (which classifies a scan *result*,
    not a malformed fixture).
    """
