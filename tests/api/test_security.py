"""Security tests for the Phase 5 API (§12, §13, §28, §30).

These are the tests that matter most in this phase. A CSPM platform that
leaks one tenant's findings to another has failed at the thing it sells,
so cross-tenant isolation and token verification are tested adversarially
rather than happy-path.
"""

from __future__ import annotations

import time

import jwt
import pytest

from application.ports.auth import Role
from infrastructure.auth.jwt_tokens import (
    ALGORITHM,
    JwtSettings,
    JwtTokenIssuer,
    RsaKeyPair,
)
from tests.api.conftest import TENANT_A, TENANT_B


def _forge_hs256(*, payload: dict, hmac_secret: bytes) -> str:
    """Hand-build an HS256 JWT, bypassing PyJWT's encoder guards.

    An attacker writes bytes, not library calls. Building the token
    manually is what makes the algorithm-confusion test a test of OUR
    verifier rather than of PyJWT's refusal to cooperate.
    """

    import base64
    import hashlib
    import hmac
    import json

    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    signing_input = header + b"." + body
    signature = b64(hmac.new(hmac_secret, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + signature).decode("ascii")


class TestAuthenticationIsRequired:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/findings",
            "/api/v1/findings/anything",
            "/api/v1/scores",
            "/api/v1/scores/current",
            "/api/v1/scans",
            "/api/v1/scans/any-scan/attack-paths",
            "/api/v1/attack-paths/anything",
        ],
    )
    def test_every_data_endpoint_rejects_an_anonymous_caller(self, client, path) -> None:
        response = client.get(path)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_error"

    def test_a_malformed_authorization_header_is_rejected(self, client) -> None:
        response = client.get("/api/v1/findings", headers={"Authorization": "not-a-scheme"})
        assert response.status_code == 401

    def test_a_bearer_header_with_no_token_is_rejected(self, client) -> None:
        response = client.get("/api/v1/findings", headers={"Authorization": "Bearer "})
        assert response.status_code == 401

    def test_garbage_instead_of_a_token_is_rejected(self, client) -> None:
        response = client.get(
            "/api/v1/findings", headers={"Authorization": "Bearer not.a.jwt"}
        )
        assert response.status_code == 401

    def test_the_401_body_never_reveals_why_it_failed(self, client) -> None:
        # Distinguishing "expired" from "bad signature" from "wrong
        # audience" hands an attacker a free oracle.
        response = client.get(
            "/api/v1/findings", headers={"Authorization": "Bearer not.a.jwt"}
        )
        message = response.json()["error"]["message"].lower()
        for leak in ("signature", "expired", "audience", "issuer", "decode", "algorithm"):
            assert leak not in message


class TestTokenForgeryIsRejected:
    def test_a_token_signed_by_a_different_key_is_rejected(self, client, settings) -> None:
        attacker = JwtTokenIssuer(key_pair=RsaKeyPair.generate(), settings=settings)
        from application.ports.auth import TokenRequest

        forged = attacker.issue(
            TokenRequest(subject="attacker", tenant_id=TENANT_A, roles=frozenset({Role.READER}))
        ).access_token
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_an_alg_none_token_is_rejected(self, client) -> None:
        # The classic JWT bypass: strip the signature and claim no
        # algorithm. Defended by passing algorithms=[RS256] explicitly.
        forged = jwt.encode(
            {
                "sub": "attacker",
                "tenant_id": str(TENANT_A),
                "roles": ["reader", "admin"],
                "iss": "complianceiq-core",
                "aud": "complianceiq",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            key="",
            algorithm="none",
        )
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_an_hs256_token_signed_with_the_public_key_is_rejected(
        self, client, key_pair
    ) -> None:
        """The algorithm-confusion attack.

        The server holds an RSA public key, which is not secret. If the
        verifier accepted whatever ``alg`` the token declared, an
        attacker could sign with HS256 using that public key as the HMAC
        secret and the server would happily verify it — forging any
        identity, for any tenant, with any role.

        Forged by hand rather than with ``jwt.encode``: PyJWT refuses to
        encode HS256 from a PEM key, but an attacker is under no such
        constraint, so using the library's encoder would test PyJWT's
        politeness instead of our verifier.
        """

        forged = _forge_hs256(
            payload={
                "sub": "attacker",
                "tenant_id": str(TENANT_A),
                "roles": ["admin", "reader", "scanner"],
                "iss": "complianceiq-core",
                "aud": "complianceiq",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            hmac_secret=key_pair.public_pem().encode("ascii"),
        )
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    def test_an_expired_token_is_rejected(self, client, key_pair, settings) -> None:
        expired = jwt.encode(
            {
                "sub": "ai-service",
                "tenant_id": str(TENANT_A),
                "roles": ["reader"],
                "iss": settings.issuer,
                "aud": settings.audience,
                "iat": int(time.time()) - 7200,
                "exp": int(time.time()) - 3600,
            },
            key_pair.sign_key(),
            algorithm=ALGORITHM,
        )
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {expired}"}
        )
        assert response.status_code == 401

    def test_a_token_for_the_wrong_audience_is_rejected(self, client, key_pair) -> None:
        other = JwtTokenIssuer(
            key_pair=key_pair, settings=JwtSettings(audience="some-other-service")
        )
        from application.ports.auth import TokenRequest

        token = other.issue(
            TokenRequest(subject="s", tenant_id=TENANT_A, roles=frozenset({Role.READER}))
        ).access_token
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401

    def test_a_token_from_the_wrong_issuer_is_rejected(self, client, key_pair) -> None:
        other = JwtTokenIssuer(key_pair=key_pair, settings=JwtSettings(issuer="evil-idp"))
        from application.ports.auth import TokenRequest

        token = other.issue(
            TokenRequest(subject="s", tenant_id=TENANT_A, roles=frozenset({Role.READER}))
        ).access_token
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401

    def test_a_token_without_a_tenant_claim_is_rejected(
        self, client, key_pair, settings
    ) -> None:
        # Must never be defaulted to some tenant — that is a
        # cross-tenant read waiting to happen.
        token = jwt.encode(
            {
                "sub": "ai-service",
                "roles": ["reader"],
                "iss": settings.issuer,
                "aud": settings.audience,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            key_pair.sign_key(),
            algorithm=ALGORITHM,
        )
        response = client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401


class TestTenantIsolation:
    def test_a_tenant_sees_only_its_own_findings(self, client, token_factory) -> None:
        headers = {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}
        body = client.get("/api/v1/findings", headers=headers).json()
        assert body["total"] == 4
        assert {item["tenant_id"] for item in body["items"]} == {"acme"}

    def test_the_other_tenant_sees_only_its_own(self, client, token_factory) -> None:
        headers = {"Authorization": f"Bearer {token_factory(tenant=TENANT_B)}"}
        body = client.get("/api/v1/findings", headers=headers).json()
        assert body["total"] == 1
        assert {item["tenant_id"] for item in body["items"]} == {"globex"}

    def test_fetching_another_tenants_finding_by_id_returns_404(
        self, client, token_factory, findings_repo
    ) -> None:
        # The whole isolation guarantee in one test: tenant B's finding
        # id is real and resolvable — just not for tenant A.
        other = next(
            f for f in findings_repo._findings if f.tenant_id == TENANT_B
        )
        headers = {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}
        response = client.get(f"/api/v1/findings/{other.id!s}", headers=headers)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    def test_a_missing_finding_and_a_foreign_finding_are_indistinguishable(
        self, client, token_factory, findings_repo
    ) -> None:
        # If these two responses differed at all, the difference would be
        # an oracle for enumerating another tenant's finding ids.
        other = next(f for f in findings_repo._findings if f.tenant_id == TENANT_B)
        headers = {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}

        foreign = client.get(f"/api/v1/findings/{other.id!s}", headers=headers)
        absent = client.get("/api/v1/findings/no-such-finding-at-all", headers=headers)

        assert foreign.status_code == absent.status_code == 404
        assert foreign.json()["error"]["code"] == absent.json()["error"]["code"]
        assert foreign.json()["error"]["message"] == absent.json()["error"]["message"]

    def test_a_tenant_id_query_parameter_cannot_change_scope(
        self, client, token_factory
    ) -> None:
        # There is no tenant_id parameter. Supplying one must not widen
        # or switch scope — it is simply ignored.
        headers = {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}
        body = client.get(
            "/api/v1/findings?tenant_id=globex", headers=headers
        ).json()
        assert {item["tenant_id"] for item in body["items"]} == {"acme"}


class TestAuthorization:
    def test_a_reader_cannot_trigger_a_scan(self, client, auth_headers) -> None:
        response = client.post(
            "/api/v1/scans", headers=auth_headers, json={"provider": "aws"}
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "authorization_error"

    def test_a_scanner_can_trigger_a_scan(self, client, scanner_headers) -> None:
        response = client.post(
            "/api/v1/scans", headers=scanner_headers, json={"provider": "aws"}
        )
        assert response.status_code == 202

    def test_a_token_with_no_roles_cannot_read(self, client, token_factory) -> None:
        headers = {"Authorization": f"Bearer {token_factory(roles=frozenset())}"}
        assert client.get("/api/v1/findings", headers=headers).status_code == 403

    def test_admin_does_not_implicitly_grant_reader(self, client, token_factory) -> None:
        # Implicit role inheritance is how an "admin" quietly acquires a
        # capability nobody granted. Roles are explicit here.
        headers = {"Authorization": f"Bearer {token_factory(roles=frozenset({Role.ADMIN}))}"}
        assert client.get("/api/v1/findings", headers=headers).status_code == 403


class TestNoSecretsLeak:
    def test_jwks_exposes_only_public_key_material(self, client) -> None:
        body = client.get("/.well-known/jwks.json").json()
        serialized = str(body)
        assert "PRIVATE" not in serialized
        # RSA private components must never appear: d, p, q, dp, dq, qi.
        for private_field in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_field not in body["keys"][0]
        assert set(body["keys"][0]) == {"kty", "use", "alg", "kid", "n", "e"}

    def test_health_is_public_but_reveals_nothing(self, client) -> None:
        body = client.get("/health").json()
        assert set(body) == {"status", "database"}

    def test_an_internal_error_does_not_leak_details(self, client, app, auth_headers) -> None:
        class Exploding:
            def execute(self, **kwargs):  # noqa: ANN003
                raise RuntimeError(
                    "connection to postgresql://user:hunter2@db:5432/prod failed"
                )

        app.state.query_findings = Exploding()
        response = client.get("/api/v1/findings", headers=auth_headers)

        assert response.status_code == 500
        body = response.json()
        assert body["error"]["code"] == "internal_error"
        assert body["error"]["message"] == "an internal error occurred"
        # The credential in the exception message must not reach the client.
        assert "hunter2" not in response.text
        assert "postgresql" not in response.text


class TestSecurityHeaders:
    def test_baseline_headers_are_present(self, client) -> None:
        headers = client.get("/health").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Cache-Control"] == "no-store"

    def test_cors_is_closed_by_default(self, client, auth_headers) -> None:
        # A permissive default is how an API becomes readable by any site
        # the user happens to visit.
        response = client.get(
            "/api/v1/findings",
            headers={**auth_headers, "Origin": "https://evil.example"},
        )
        assert "access-control-allow-origin" not in {
            k.lower() for k in response.headers
        }
