"""Correlation IDs and structured request logging (Phase 5, §16, §29).

§16's requirement is precise: accept ``X-Correlation-ID`` if the caller
sends one, generate one if not, return it on the response, and make it
available to propagate downstream. One id follows a request from the
dashboard through Core to the AI Service, which is the difference
between debugging a distributed system and guessing about it.

The logging half is equally constrained by what it must NOT do. The
access log records correlation id, tenant, subject, method, path,
status and duration. It never records the Authorization header, the
token, the query string, or the response body — a query string can
carry a resource id, and a token is a live credential that would sit in
the log until rotation.
"""

from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from presentation.errors import CORRELATION_HEADER

logger = logging.getLogger("complianceiq.access")

#: Cap on an inbound correlation id. It is attacker-controlled text that
#: lands in every log line for the request, so it is length-limited and
#: sanitized rather than trusted — an unbounded value is a cheap way to
#: bloat logs, and control characters can forge log lines.
MAX_CORRELATION_ID_LENGTH = 128


def _sanitize(raw: str) -> str | None:
    """Accept a caller-supplied id only if it is safe to log verbatim."""

    candidate = raw.strip()
    if not candidate or len(candidate) > MAX_CORRELATION_ID_LENGTH:
        return None
    # Printable ASCII without whitespace: enough for UUIDs, ULIDs and
    # trace ids, and no newline that could inject a fake log record.
    if not all(33 <= ord(ch) <= 126 for ch in candidate):
        return None
    return candidate


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Establish a correlation id for every request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get(CORRELATION_HEADER)
        correlation_id = (_sanitize(supplied) if supplied else None) or str(uuid.uuid4())

        # Available to error handlers, audit records, and any downstream
        # client built during this request.
        request.state.correlation_id = correlation_id

        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000

        response.headers[CORRELATION_HEADER] = correlation_id

        identity = getattr(request.state, "identity", None)
        logger.info(
            "%s %s -> %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "correlation_id": correlation_id,
                # Present only once authentication has succeeded; absent
                # on a 401, which is itself informative.
                "tenant_id": str(identity.tenant_id) if identity else None,
                "subject": identity.subject if identity else None,
                "method": request.method,
                # Path only. The query string can carry resource ids.
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline security response headers (§28).

    This is a JSON API, not an HTML app, so the set is deliberately
    small — a CSP tuned for documents would be cargo-culting. These
    three are the ones that matter for an API:

    * ``nosniff`` stops a browser from re-interpreting a JSON response
      as HTML or script, which is the vector behind JSON-based XSS.
    * ``DENY`` framing: nothing here should ever render in a frame.
    * ``no-store`` keeps authenticated responses — which contain tenant
      data — out of shared caches and browser disk cache.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
