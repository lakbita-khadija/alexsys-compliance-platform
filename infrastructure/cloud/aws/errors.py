"""AWS-specific Infrastructure exceptions.

Kept specific on purpose (blueprint Phase 3 brief, §11): a missing IAM
permission, an expired/invalid credential, and a throttled AWS API call
are three different problems an operator needs to tell apart at a
glance. ``translate_client_error`` maps a ``botocore.exceptions.ClientError``
to the right one of these based on its AWS error code — no exception is
ever silently downgraded to a generic message.
"""

from __future__ import annotations

from infrastructure.errors import InfrastructureError


class AwsError(InfrastructureError):
    """Base class for every AWS-specific Infrastructure exception."""


class AwsAuthenticationError(AwsError):
    """The AWS credentials themselves are missing, invalid, or expired."""


class AwsPermissionError(AwsError):
    """The caller is authenticated but lacks the IAM permission required."""


class AwsServiceError(AwsError):
    """AWS itself failed the request (throttling, internal error,
    service unavailable) — not a credential or permission problem.
    """


class AwsCollectionError(AwsError):
    """A specific resource type failed to collect.

    Raised by each per-service sub-collector's isolation wrapper
    (blueprint §6's ``_safe()`` pattern: "un échec sur un service
    n'empêche pas la collecte des autres") so ``AwsCollector`` can skip
    just that one service and continue collecting the rest, while still
    surfacing exactly what failed and why (the original cause is always
    preserved via ``raise ... from``).
    """


_AUTHENTICATION_ERROR_CODES = frozenset(
    {
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "ExpiredToken",
        "ExpiredTokenException",
        "AuthFailure",
        "SignatureDoesNotMatch",
        "MissingAuthenticationToken",
    }
)

_PERMISSION_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Forbidden",
    }
)


def translate_client_error(exc: Exception, *, context: str) -> AwsError:
    """Map a ``botocore.exceptions.ClientError`` to the specific
    ``AwsError`` subclass its error code indicates. Any other exception
    type (network failure, unexpected shape) becomes ``AwsServiceError``
    — still specific to "AWS/network failed", never a bare
    ``AwsError``.
    """

    error_code = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error_code = response.get("Error", {}).get("Code")

    message = f"{context}: {exc}"

    if error_code in _AUTHENTICATION_ERROR_CODES:
        return AwsAuthenticationError(message)
    if error_code in _PERMISSION_ERROR_CODES:
        return AwsPermissionError(message)
    return AwsServiceError(message)
