"""Infrastructure-layer exceptions.

Deliberately not a subclass of ``domain.shared.errors.DomainError`` or
``application.errors.ApplicationError`` — Infrastructure is a distinct
layer with its own failure modes (a throttled AWS API call is not a
business-rule violation and not a port-contract violation; it's a
technical failure of a concrete adapter). Every exception here is
specific enough to be diagnosable: a missing IAM permission must never
look identical to a network timeout.
"""

from __future__ import annotations


class InfrastructureError(Exception):
    """Base class for every exception raised by the Infrastructure layer."""
