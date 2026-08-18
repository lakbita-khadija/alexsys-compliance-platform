"""Authentication and authorization ports (Phase 5, §13).

The use cases below the API need to know *who is asking* and *for which
tenant*. They must not need to know that the answer arrived in a JWT, or
that the JWT was RS256, or that PyJWT parsed it. That is the entire
purpose of this module: ``AuthenticatedIdentity`` is the only thing the
application layer ever sees, and swapping JWT for mTLS or an opaque
session token later would not change a single use case.

The security-critical rule lives here rather than in a router:

    The tenant comes from the VERIFIED token. Never from a query
    parameter, a header, a path segment, or a request body.

``AuthenticatedIdentity`` is constructed only by a ``TokenVerifier``
implementation, which means the only way to obtain one is to have
verified a signature. A route handler cannot fabricate an identity
without deliberately importing this class and constructing it by hand,
which is visible in review.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping

from domain.shared.identifiers import TenantId


class AuthenticationError(Exception):
    """The caller could not be authenticated: missing, malformed,
    expired, or improperly signed credentials. Maps to HTTP 401.

    Carries a ``reason`` for logging that is deliberately NOT the
    message returned to the client — telling an attacker whether a token
    failed on signature versus expiry versus audience is free
    reconnaissance.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthorizationError(Exception):
    """The caller is authenticated but lacks the required role.
    Maps to HTTP 403.
    """


class Role(str, Enum):
    """The closed role vocabulary.

    Small on purpose. Phase 5's brief (§27) explicitly defers full RBAC,
    so this covers only what the API actually enforces today: who may
    read platform data, and who may cause a scan to run. Anything finer
    would be speculative.
    """

    #: Read platform data: findings, scores, scans. What the AI Service
    #: and the dashboard need.
    READER = "reader"
    #: Trigger scans. Separated from READER because starting a scan
    #: spends real money and hits real cloud APIs.
    SCANNER = "scanner"
    #: Administrative operations. Reserved; no endpoint requires it yet.
    ADMIN = "admin"


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    """A verified caller.

    Obtainable only from a ``TokenVerifier``, so possessing one is proof
    that a signature was checked.
    """

    subject: str
    tenant_id: TenantId
    roles: frozenset[Role]
    issuer: str
    audience: str
    expires_at: datetime
    #: The token's own id (``jti``), when present. Recorded in audit
    #: events so a specific credential can be traced, WITHOUT storing
    #: the token itself.
    token_id: str | None = None

    def has_role(self, role: Role) -> bool:
        # ADMIN deliberately does NOT imply the other roles. Implicit
        # role inheritance is how an "admin" quietly gains a capability
        # nobody granted; if an admin needs to read findings, the token
        # says so.
        return role in self.roles

    def require_role(self, role: Role) -> None:
        """Raise ``AuthorizationError`` unless the caller holds ``role``."""

        if not self.has_role(role):
            raise AuthorizationError(
                f"this operation requires the '{role.value}' role"
            )


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """What to mint a token for.

    ``tenant_id`` is supplied by the *issuer's* caller — a trusted,
    server-side path (client-credentials validation) — never by an
    end user asking for a token for an arbitrary tenant.
    """

    subject: str
    tenant_id: TenantId
    roles: frozenset[Role]
    #: Lifetime in seconds. Bounded by the implementation; a token that
    #: never expires is a permanent credential.
    lifetime_seconds: int = 3600


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A minted token and the metadata a client needs to use it."""

    access_token: str
    token_type: str
    expires_in: int
    expires_at: datetime
    token_id: str

    def __repr__(self) -> str:  # pragma: no cover - trivial, security-relevant
        # The token is a bearer credential: anything holding it can act
        # as the subject. Keeping it out of reprs keeps it out of
        # tracebacks and debug logs, which is where credentials usually
        # escape.
        return (
            f"IssuedToken(token_type={self.token_type!r}, expires_in={self.expires_in}, "
            f"token_id={self.token_id!r}, access_token=<redacted>)"
        )


class TokenVerifier(ABC):
    """Port: turn a raw credential into a verified identity."""

    @abstractmethod
    def verify(self, raw_token: str) -> AuthenticatedIdentity:
        """Verify signature, issuer, audience, expiry and required
        claims, and return the identity.

        Raises ``AuthenticationError`` on ANY failure. Implementations
        must not return a partially-trusted identity, and must not fall
        back to an unverified decode.
        """


class TokenIssuer(ABC):
    """Port: mint credentials.

    Separate from ``TokenVerifier`` because the two have very different
    blast radii — verification needs only the public key, issuance needs
    the private one. A deployment that only verifies (an external IdP
    signs) implements one and not the other.
    """

    @abstractmethod
    def issue(self, request: TokenRequest) -> IssuedToken:
        """Mint a signed token."""

    @abstractmethod
    def public_jwks(self) -> Mapping[str, Any]:
        """The public verification keys, in JWKS form.

        Published so the AI Service can verify tokens offline without
        calling Core on every request, and so key rotation does not
        require redeploying consumers. Must NEVER include private key
        material — implementations are expected to derive this from the
        public key only.
        """
