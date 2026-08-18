"""Azure authenticated identity, from the access token (STEP 6.5).

The problem this solves, from `cloud-auth-readiness.md` §3.2/§3.3:

* `AzureSessionFactory` passed the configured Entra tenant as
  `DefaultAzureCredential(interactive_browser_tenant_id=...)`, which
  scopes **only the interactive-browser sub-credential**. Under managed
  identity, workload identity or an environment service principal — the
  paths a production scanner actually uses — the value was silently
  ignored. The parameter reads like a constraint and is not one.
* The subscription id was passed straight into five client constructors
  and never verified, and the collector carried a comment asserting that
  no identity round trip was needed. That reasoning conflates *what we
  intend to scan* with *who we are authenticated as*.

**Where the authoritative answer lives.** Azure does not offer a
`GetCallerIdentity`. What it does offer is the access token itself: an
Entra-issued JWT whose `tid` claim is the directory that authenticated
and whose `oid` is the principal. Acquiring a token also forces the
credential chain to resolve *now* rather than at the first collector
call, which fixes the "authentication failures surface late, attributed
to the wrong component" problem in the same move.

**On decoding a token without verifying its signature.** We do it, and
it is safe *here* for a specific reason worth stating rather than
assuming: this token is not an untrusted input. We just obtained it
ourselves, over TLS, from the Azure SDK, and we are not using it to
authorize anybody — we are reading which directory our own credential
belongs to. Verifying the signature would require fetching Entra's JWKS
and would defend against an attacker who can already control our SDK's
network responses, at which point the scan is compromised regardless.
The claim is used only for a mismatch check that fails closed.

Contrast with `infrastructure/auth/jwt_tokens.py`, where a token arrives
from a caller and every signature, issuer, audience and expiry check is
mandatory. Same file format, opposite trust posture, and the difference
is who produced the token.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Protocol

from domain.shared.enums import CloudProvider
from domain.tenants.cloud_accounts import AuthenticatedCloudIdentity
from infrastructure.cloud.azure.errors import translate_azure_error

#: The management-plane scope. Requesting it proves the credential can
#: actually talk to ARM, which is what the collectors need — a token for
#: some other audience would authenticate and then fail at first use.
ARM_SCOPE = "https://management.azure.com/.default"


class _TokenCredential(Protocol):
    """The one method we need from any azure-identity credential."""

    def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...


def _claims_of(token: str) -> dict[str, Any]:
    """Read an Entra token's claims. See the module docstring on trust.

    Decoded by hand rather than with PyJWT, and the reason is
    architectural rather than stylistic. ``tests/api/test_architecture.py``
    asserts that **exactly one** module imports ``jwt``, because a second
    importer is how a codebase acquires two token implementations that
    disagree — one that checks the audience and one that does not.

    We do not want any of PyJWT's semantics here. We are not verifying a
    token; we are reading one field out of a token we just minted
    ourselves. Doing it with base64 makes that structural: this function
    *cannot* accidentally grow into a second verifier, because it has no
    verification library in scope.

    Real verification lives in ``infrastructure/auth/jwt_tokens.py`` and
    stays the only place that word applies.
    """

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a three-part JWT")

    payload = parts[1]
    # base64url without padding, which is what JWT uses. Restore it.
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    if not isinstance(claims, dict):
        raise ValueError("token payload is not an object")
    return claims


class AzureIdentityProvider:
    """Resolve the authenticated Entra tenant and subscription.

    Implements ``CloudIdentityProvider``. The subscription is *reported*
    from configuration because a token says nothing about which
    subscription we intend to scan — but pairing it with the token's real
    `tid` is what makes the binding check meaningful: a subscription is
    only trustworthy in combination with the directory that owns it, and
    a subscription can be moved between directories.
    """

    def __init__(self, *, credential: _TokenCredential, subscription_id: str) -> None:
        self._credential = credential
        self._subscription_id = subscription_id

    def authenticated_identity(self) -> AuthenticatedCloudIdentity:
        try:
            token = self._credential.get_token(ARM_SCOPE)
        except Exception as exc:  # noqa: BLE001 - any refusal means "unidentified"
            raise translate_azure_error(
                exc, context="acquiring an Azure management token"
            ) from exc

        raw = getattr(token, "token", None)
        if not isinstance(raw, str) or not raw.strip():
            raise translate_azure_error(
                ValueError("credential returned no access token"),
                context="acquiring an Azure management token",
            )

        try:
            claims = _claims_of(raw)
        except Exception as exc:  # noqa: BLE001 - a token we cannot read is not an identity
            raise translate_azure_error(
                # The exception TYPE only. A decode error's message can
                # echo token bytes, and the token is a bearer credential.
                ValueError(f"access token could not be decoded ({type(exc).__name__})"),
                context="reading the Azure token identity",
            ) from exc

        directory_id = claims.get("tid")
        if not isinstance(directory_id, str) or not directory_id.strip():
            # Without `tid` we cannot tell which directory authenticated,
            # which is the entire question this class exists to answer.
            raise translate_azure_error(
                ValueError("access token carries no 'tid' claim"),
                context="reading the Azure token identity",
            )

        principal = claims.get("oid") or claims.get("appid") or claims.get("sub")
        return AuthenticatedCloudIdentity(
            provider=CloudProvider.AZURE,
            account_id=self._subscription_id,
            directory_id=directory_id.strip(),
            principal=principal if isinstance(principal, str) and principal.strip() else None,
        )


__all__ = ["ARM_SCOPE", "AzureIdentityProvider"]
