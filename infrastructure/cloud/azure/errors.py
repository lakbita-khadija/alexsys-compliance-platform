"""Azure-specific Infrastructure exceptions.

Mirrors ``infrastructure.cloud.aws.errors`` deliberately: the same four
failure categories (authentication / permission / service / collection),
because an operator debugging a failed scan needs to tell those apart at
a glance regardless of which cloud produced them. The two hierarchies
are separate classes rather than one shared set, for the same reason
``AwsError`` is not a generic ``CloudError``: the *translation* logic is
entirely provider-specific (Azure signals permission denial with an
HTTP 403 on an ``HttpResponseError``; AWS uses a string error code on a
``ClientError``), and collapsing them would force a lowest-common-
denominator translator that loses information from both.

``translate_azure_error`` maps Azure SDK exceptions to the right
subclass using the HTTP status code, which is the one signal the Azure
management SDKs report consistently across every service client.
"""

from __future__ import annotations

from infrastructure.errors import InfrastructureError


class AzureError(InfrastructureError):
    """Base class for every Azure-specific Infrastructure exception."""


class AzureAuthenticationError(AzureError):
    """The Azure credentials themselves are missing, invalid, or expired."""


class AzurePermissionError(AzureError):
    """The caller is authenticated but lacks the RBAC role required."""


class AzureServiceError(AzureError):
    """Azure itself failed the request (throttling, internal error,
    service unavailable) — not a credential or permission problem.
    """


class AzureCollectionError(AzureError):
    """A specific resource type failed to collect.

    Raised by each per-service sub-collector's isolation wrapper so
    ``AzureCollector`` can skip just that one service and continue
    collecting the rest, while still surfacing exactly what failed and
    why (the original cause is always preserved via ``raise ... from``).
    Same contract as ``AwsCollectionError``.
    """


_AUTHENTICATION_STATUS_CODES = frozenset({401})
_PERMISSION_STATUS_CODES = frozenset({403})


def translate_azure_error(exc: Exception, *, context: str) -> AzureError:
    """Map an Azure SDK exception to the specific ``AzureError``
    subclass its HTTP status code indicates.

    ``azure.core.exceptions.ClientAuthenticationError`` is recognized by
    name rather than by import, so this module (and every collector that
    imports it) stays importable and unit-testable without the Azure SDK
    installed — the same reason the AWS translator inspects
    ``exc.response`` duck-typed rather than isinstance-checking
    ``ClientError``.
    """

    message = f"{context}: {exc}"

    if type(exc).__name__ == "ClientAuthenticationError":
        return AzureAuthenticationError(message)

    status_code = getattr(exc, "status_code", None)
    if status_code in _AUTHENTICATION_STATUS_CODES:
        return AzureAuthenticationError(message)
    if status_code in _PERMISSION_STATUS_CODES:
        return AzurePermissionError(message)

    return AzureServiceError(message)
