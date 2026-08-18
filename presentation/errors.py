"""The error contract (Phase 5, §17, §18).

Every error this API returns has the same shape:

    {"error": {"code": ..., "message": ..., "correlation_id": ..., "details": {}}}

Including validation errors, including 500s, including errors raised
inside FastAPI before any of our code runs. A single response shape is
what lets the AI Service write one error handler instead of guessing;
an API that returns its own envelope for expected errors and FastAPI's
``{"detail": ...}`` for unexpected ones has two contracts, and the
second one is undocumented.

``code`` is the machine-readable part and is treated as frozen: clients
branch on it, so changing a code is a breaking change requiring a
version bump (§20). ``message`` is for humans and may be reworded.

**Nothing internal is ever exposed.** No stack traces, no SQL, no
exception messages from the database or a cloud provider, no credentials.
The handler for unexpected exceptions deliberately discards the original
message and returns a fixed string — the detail goes to the log, keyed
by correlation id, where an operator can find it and an attacker cannot.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Mapping

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from application.ports.auth import AuthenticationError, AuthorizationError
from application.ports.queries import InvalidQuery
from application.scanning.submit_scan import ScanConflict
from domain.shared.errors import DomainError, TenantIsolationViolation

logger = logging.getLogger("complianceiq.api")

#: Header carrying the request correlation id, in and out (§16).
CORRELATION_HEADER = "X-Correlation-ID"


class ErrorCode(str, Enum):
    """Stable, machine-readable error codes (§17).

    Treated as part of the v1 contract. Adding a code is additive and
    safe; changing or removing one is breaking.
    """

    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    TENANT_ISOLATION_VIOLATION = "tenant_isolation_violation"
    NOT_FOUND = "not_found"
    VALIDATION_ERROR = "validation_error"
    INVALID_FILTER = "invalid_filter"
    SCAN_CONFLICT = "scan_conflict"
    SCAN_FAILED = "scan_failed"
    PROVIDER_ERROR = "provider_error"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


class ApiError(Exception):
    """An error with a known code and status, raised by routers.

    Carrying the HTTP status on the exception keeps the mapping next to
    the reason it was raised, instead of in a lookup table that drifts.
    """

    def __init__(
        self,
        *,
        code: ErrorCode,
        message: str,
        status_code: int,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details: Mapping[str, Any] = details or {}


def not_found(resource: str) -> ApiError:
    """The 404 used for both "absent" and "belongs to another tenant".

    A single constructor so the two cases are impossible to distinguish
    by message as well as by status (§12). If one path said "finding not
    found" and the other "access denied", the isolation guarantee would
    leak through the wording.
    """

    return ApiError(
        code=ErrorCode.NOT_FOUND,
        message=f"{resource} not found",
        status_code=status.HTTP_404_NOT_FOUND,
    )


def _correlation_id(request: Request) -> str:
    # Set by CorrelationIdMiddleware; the fallback keeps error handling
    # working even if an error occurs before the middleware ran.
    return getattr(request.state, "correlation_id", "unknown")


def _envelope(
    *,
    code: ErrorCode,
    message: str,
    correlation_id: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code.value,
            "message": message,
            "correlation_id": correlation_id,
            "details": dict(details or {}),
        }
    }


def _response(
    request: Request,
    *,
    code: ErrorCode,
    message: str,
    status_code: int,
    details: Mapping[str, Any] | None = None,
) -> JSONResponse:
    correlation_id = _correlation_id(request)
    return JSONResponse(
        status_code=status_code,
        content=_envelope(
            code=code, message=message, correlation_id=correlation_id, details=details
        ),
        # Echoed on errors too — an error is exactly when a caller most
        # needs the id to correlate with our logs.
        headers={CORRELATION_HEADER: correlation_id},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install every handler needed to guarantee one response shape."""

    @app.exception_handler(ApiError)
    async def _handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _response(
            request,
            code=exc.code,
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
        )

    @app.exception_handler(AuthenticationError)
    async def _handle_auth(request: Request, exc: AuthenticationError) -> JSONResponse:
        # The specific reason (bad signature? expired? wrong audience?)
        # is logged, never returned: telling an attacker which check
        # failed is free reconnaissance.
        logger.warning(
            "authentication failed",
            extra={"correlation_id": _correlation_id(request), "reason": exc.reason},
        )
        return _response(
            request,
            code=ErrorCode.AUTHENTICATION_ERROR,
            message="authentication required",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    @app.exception_handler(AuthorizationError)
    async def _handle_authz(request: Request, exc: AuthorizationError) -> JSONResponse:
        return _response(
            request,
            code=ErrorCode.AUTHORIZATION_ERROR,
            message=str(exc),
            status_code=status.HTTP_403_FORBIDDEN,
        )

    @app.exception_handler(TenantIsolationViolation)
    async def _handle_isolation(
        request: Request, exc: TenantIsolationViolation
    ) -> JSONResponse:
        # Reaching here means a defense-in-depth check fired: the caller
        # got past routing with data belonging to another tenant. That is
        # a serious internal signal, logged at ERROR, and answered with a
        # generic 404 so the prober learns nothing.
        logger.error(
            "tenant isolation violation",
            extra={"correlation_id": _correlation_id(request)},
        )
        return _response(
            request,
            code=ErrorCode.NOT_FOUND,
            message="resource not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    @app.exception_handler(ScanConflict)
    async def _handle_conflict(request: Request, exc: ScanConflict) -> JSONResponse:
        return _response(
            request,
            code=ErrorCode.SCAN_CONFLICT,
            message=str(exc),
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(InvalidQuery)
    async def _handle_invalid_query(request: Request, exc: InvalidQuery) -> JSONResponse:
        # Safe to echo: InvalidQuery messages are written by us and
        # describe the caller's own input ("limit must not exceed 100").
        return _response(
            request,
            code=ErrorCode.INVALID_FILTER,
            message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI's default returns a bare {"detail": [...]}, which would
        # be a second, undocumented error shape. Re-wrapped here.
        details = {
            "fields": [
                {
                    "location": ".".join(str(p) for p in err.get("loc", ())),
                    "message": err.get("msg", "invalid value"),
                }
                for err in exc.errors()
            ]
        }
        return _response(
            request,
            code=ErrorCode.VALIDATION_ERROR,
            message="request validation failed",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Covers 404s from unmatched routes and 405s from wrong methods,
        # which otherwise bypass our envelope entirely.
        code = {
            401: ErrorCode.AUTHENTICATION_ERROR,
            403: ErrorCode.AUTHORIZATION_ERROR,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.SCAN_CONFLICT,
            429: ErrorCode.RATE_LIMITED,
            503: ErrorCode.SERVICE_UNAVAILABLE,
        }.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
        return _response(
            request,
            code=code,
            message=str(exc.detail),
            status_code=exc.status_code,
        )

    @app.exception_handler(DomainError)
    async def _handle_domain(request: Request, exc: DomainError) -> JSONResponse:
        # A domain invariant rejected the request. The message describes
        # a rule ("severity must be a Severity"), not internals, so it is
        # safe and genuinely useful to return.
        return _response(
            request,
            code=ErrorCode.VALIDATION_ERROR,
            message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = _correlation_id(request)
        # exc_info goes to the log, where operators can see it. The
        # RESPONSE gets a fixed string: an unexpected exception's message
        # may contain a SQL fragment, a file path, or a connection string.
        logger.exception(
            "unhandled exception", extra={"correlation_id": correlation_id}
        )
        return _response(
            request,
            code=ErrorCode.INTERNAL_ERROR,
            message="an internal error occurred",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
