"""RS256 JWT issuance and verification (Phase 5, §13).

The only module in the system that knows what a JWT is. Everything above
it sees ``AuthenticatedIdentity``.

## Why asymmetric

RS256, not HS256. With a shared secret, every service that *verifies* a
token can also *mint* one — so the AI Service, which only needs to check
signatures, would hold a credential that lets it impersonate any tenant.
With RS256 the private key never leaves Core, and consumers verify with
a public key published at the JWKS endpoint.

## What verification actually checks

Signature, issuer, audience, expiry, and the presence and shape of every
required claim. All of them, every time. The two failure modes worth
naming because they are the classic JWT vulnerabilities:

* ``algorithms=[RS256]`` is passed explicitly to ``jwt.decode``. Without
  it, a token with ``"alg": "none"`` — or one signed with HS256 using
  the *public* key as the shared secret — verifies successfully. This is
  the single most exploited JWT flaw and the defence is one argument.
* ``tenant_id`` is required and non-blank. A token without it is
  rejected rather than defaulted, because a default tenant is a
  cross-tenant read waiting to happen.

Failures raise ``AuthenticationError`` with a specific ``reason`` for
the log and a generic message for the client (see presentation/errors.py).
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from application.ports.auth import (
    AuthenticatedIdentity,
    AuthenticationError,
    IssuedToken,
    Role,
    TokenIssuer,
    TokenRequest,
    TokenVerifier,
)
from domain.shared.identifiers import TenantId

ALGORITHM = "RS256"

#: Upper bound on token lifetime. A long-lived bearer token is a
#: long-lived credential: it cannot be revoked before it expires (there
#: is no revocation list in Phase 5), so the expiry IS the revocation
#: mechanism and must stay short.
MAX_LIFETIME_SECONDS = 24 * 3600


def _b64url_uint(value: int) -> str:
    """Encode an integer as base64url, per RFC 7518 for JWK n/e."""

    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class JwtSettings:
    """Issuer/audience configuration.

    Defaults match §13 exactly (``complianceiq-core`` / ``complianceiq``)
    so a stock deployment interoperates with the AI Service without
    either side configuring anything.
    """

    issuer: str = "complianceiq-core"
    audience: str = "complianceiq"
    key_id: str = "core-1"
    default_lifetime_seconds: int = 3600


class RsaKeyPair:
    """Holds the signing key.

    The private key is never rendered: no ``__repr__``, no ``__str__``,
    no property returning PEM. Only the PUBLIC half is exportable, and
    only as JWKS. A key object that can print itself ends up in a
    traceback eventually.
    """

    def __init__(self, private_key: RSAPrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls, key_size: int = 2048) -> "RsaKeyPair":
        """Generate a fresh key pair.

        For development and tests. A production deployment loads a
        managed key via ``from_pem`` — a key generated at boot would
        invalidate every outstanding token on every restart and could
        not be shared across replicas.
        """

        return cls(rsa.generate_private_key(public_exponent=65537, key_size=key_size))

    @classmethod
    def from_pem(cls, pem: str | bytes, *, password: bytes | None = None) -> "RsaKeyPair":
        """Load a PKCS#8 PEM private key, typically from an environment
        variable or a mounted secret. Never from a file in this repo.
        """

        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"expected an RSA private key, got {type(key).__name__}")
        return cls(key)

    @property
    def _public_key(self) -> RSAPublicKey:
        return self._private_key.public_key()

    def sign_key(self) -> RSAPrivateKey:
        return self._private_key

    def verify_key(self) -> RSAPublicKey:
        return self._public_key

    def public_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def jwks(self, key_id: str) -> dict[str, Any]:
        """The public key in JWKS form — public numbers only."""

        numbers = self._public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": ALGORITHM,
                    "kid": key_id,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }

    def __repr__(self) -> str:  # pragma: no cover - security-relevant, trivial
        return "RsaKeyPair(<private key withheld>)"


class JwtTokenIssuer(TokenIssuer):
    """Mints RS256 tokens."""

    def __init__(self, *, key_pair: RsaKeyPair, settings: JwtSettings | None = None) -> None:
        self._keys = key_pair
        self._settings = settings or JwtSettings()

    def issue(self, request: TokenRequest) -> IssuedToken:
        lifetime = min(request.lifetime_seconds, MAX_LIFETIME_SECONDS)
        if lifetime < 1:
            raise ValueError("lifetime_seconds must be positive")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lifetime)
        token_id = str(uuid.uuid4())

        claims = {
            "sub": request.subject,
            "tenant_id": str(request.tenant_id),
            # Sorted so the same request always produces the same claim
            # ordering — one less thing to differ between two tokens
            # that should be equivalent.
            "roles": sorted(role.value for role in request.roles),
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": token_id,
        }

        token = jwt.encode(
            claims,
            self._keys.sign_key(),
            algorithm=ALGORITHM,
            headers={"kid": self._settings.key_id},
        )

        return IssuedToken(
            access_token=token,
            token_type="Bearer",
            expires_in=lifetime,
            expires_at=expires_at,
            token_id=token_id,
        )

    def public_jwks(self) -> Mapping[str, Any]:
        return self._keys.jwks(self._settings.key_id)


class JwtTokenVerifier(TokenVerifier):
    """Verifies RS256 tokens.

    Constructed with only the PUBLIC key in a deployment that does not
    issue — which is what the AI Service would do if it verified locally.
    """

    def __init__(
        self,
        *,
        public_key: RSAPublicKey | RsaKeyPair,
        settings: JwtSettings | None = None,
    ) -> None:
        self._public_key = (
            public_key.verify_key() if isinstance(public_key, RsaKeyPair) else public_key
        )
        self._settings = settings or JwtSettings()

    def verify(self, raw_token: str) -> AuthenticatedIdentity:
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise AuthenticationError("empty token")

        try:
            claims = jwt.decode(
                raw_token,
                self._public_key,
                # Explicit. Without this a token claiming "alg": "none",
                # or one signed with HS256 using the public key as the
                # HMAC secret, would be accepted.
                algorithms=[ALGORITHM],
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("token expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError("wrong audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError("wrong issuer") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthenticationError("invalid signature") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthenticationError(f"missing required claim: {exc.claim}") from exc
        except jwt.InvalidTokenError as exc:
            # Catch-all for malformed tokens, bad segments, wrong alg.
            raise AuthenticationError(f"invalid token: {type(exc).__name__}") from exc

        return self._identity_from(claims)

    def _identity_from(self, claims: Mapping[str, Any]) -> AuthenticatedIdentity:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("sub claim missing or blank")

        # The security-critical claim. Never defaulted: a token without a
        # tenant must be rejected, not silently assigned one.
        raw_tenant = claims.get("tenant_id")
        if not isinstance(raw_tenant, str) or not raw_tenant.strip():
            raise AuthenticationError("tenant_id claim missing or blank")

        raw_roles = claims.get("roles", [])
        if not isinstance(raw_roles, (list, tuple)):
            raise AuthenticationError("roles claim must be an array")

        # An unrecognized role is ignored rather than fatal: a newer
        # issuer may mint roles this deployment does not know yet, and
        # failing closed on the whole token would break rollout. Ignoring
        # is safe because an unknown role grants nothing.
        roles = frozenset(
            Role(role) for role in raw_roles if isinstance(role, str) and role in Role._value2member_map_
        )

        return AuthenticatedIdentity(
            subject=subject,
            tenant_id=TenantId(raw_tenant),
            roles=roles,
            issuer=str(claims.get("iss", "")),
            audience=str(claims.get("aud", "")),
            expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc),
            token_id=claims.get("jti") if isinstance(claims.get("jti"), str) else None,
        )
