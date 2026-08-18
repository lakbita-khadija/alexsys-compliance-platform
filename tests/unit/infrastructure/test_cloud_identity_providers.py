"""STEP 6.5 — the adapters that answer "who did we authenticate as?".

These are the components that make the binding check mean anything. A
directory of expectations compared against *configuration* proves
nothing; it has to be compared against what the provider says.

So the load-bearing tests here are the ones asserting these adapters
**raise** rather than return a fallback. `AwsCollector._resolve_account_id`
swallows STS failures and returns `None` — correct for a descriptive
label, fatal for a gate. Both behaviours now exist in the codebase on
purpose and must not converge.
"""

from __future__ import annotations

import base64
import json

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import CloudProvider
from infrastructure.cloud.aws.errors import AwsError
from infrastructure.cloud.aws.identity import AwsIdentityProvider
from infrastructure.cloud.azure.errors import AzureError
from infrastructure.cloud.azure.identity import ARM_SCOPE, AzureIdentityProvider

ACCOUNT = "111111111111"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/complianceiq-scanner"
DIRECTORY = "dddddddd-0000-0000-0000-00000000000a"
SUBSCRIPTION = "aaaaaaaa-0000-0000-0000-000000000001"


# ---------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------


class FakeStsSession:
    """Serves exactly one client, and only `sts`."""

    def __init__(self, *, response=None, error: Exception | None = None) -> None:
        self._response = response
        self._error = error
        self.calls: list[str] = []

    def client(self, service_name: str):
        assert service_name == "sts", f"unexpected client: {service_name}"
        outer = self

        class _Sts:
            def get_caller_identity(self):
                outer.calls.append("get_caller_identity")
                if outer._error is not None:
                    raise outer._error
                return outer._response

        return _Sts()


def sts_ok(account=ACCOUNT, arn=ROLE_ARN):
    return FakeStsSession(
        response={"Account": account, "Arn": arn, "UserId": "AROAEXAMPLE:session"}
    )


class TestAwsIdentity:
    def test_it_reports_the_account_sts_returned(self) -> None:
        identity = AwsIdentityProvider(sts_ok()).authenticated_identity()
        assert identity.account_id == ACCOUNT
        assert identity.provider is CloudProvider.AWS

    def test_it_records_the_principal_arn(self) -> None:
        # For the audit trail. An ARN is an identifier, not a credential.
        assert AwsIdentityProvider(sts_ok()).authenticated_identity().principal == ROLE_ARN

    def test_aws_has_no_directory(self) -> None:
        # Azure's Entra tenant has no AWS analogue; inventing one would
        # make the two providers look symmetric when they are not.
        assert AwsIdentityProvider(sts_ok()).authenticated_identity().directory_id is None

    def test_it_actually_calls_sts(self) -> None:
        session = sts_ok()
        AwsIdentityProvider(session).authenticated_identity()
        assert session.calls == ["get_caller_identity"]

    def test_the_account_is_stripped(self) -> None:
        assert (
            AwsIdentityProvider(sts_ok(account=f"  {ACCOUNT} ")).authenticated_identity().account_id
            == ACCOUNT
        )


class TestAwsIdentityFailsLoudly:
    """Every one of these must raise. None may return a partial identity."""

    def test_access_denied_raises(self) -> None:
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity"
        )
        with pytest.raises(AwsError):
            AwsIdentityProvider(FakeStsSession(error=error)).authenticated_identity()

    def test_invalid_credentials_raise(self) -> None:
        error = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "bad key"}},
            "GetCallerIdentity",
        )
        with pytest.raises(AwsError):
            AwsIdentityProvider(FakeStsSession(error=error)).authenticated_identity()

    def test_expired_credentials_raise(self) -> None:
        error = ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "GetCallerIdentity"
        )
        with pytest.raises(AwsError):
            AwsIdentityProvider(FakeStsSession(error=error)).authenticated_identity()

    def test_missing_credentials_raise(self) -> None:
        from botocore.exceptions import NoCredentialsError

        with pytest.raises(AwsError):
            AwsIdentityProvider(
                FakeStsSession(error=NoCredentialsError())
            ).authenticated_identity()

    def test_a_network_failure_raises(self) -> None:
        with pytest.raises(AwsError):
            AwsIdentityProvider(
                FakeStsSession(error=OSError("connection reset"))
            ).authenticated_identity()

    @pytest.mark.parametrize(
        "response",
        [
            {},                              # no Account key
            {"Account": ""},                 # blank
            {"Account": "   "},              # whitespace
            {"Account": None},               # null
            {"Account": 111111111111},       # wrong type
            "not-a-dict",                    # wrong shape entirely
        ],
    )
    def test_a_malformed_response_raises(self, response) -> None:
        # An unparseable response is not an identity. Returning a blank
        # account would hand the binding check an empty string, which
        # matches nothing — so the gate would appear to work while
        # failing for the wrong reason, and the log would say "account
        # not bound" instead of "STS gave us nonsense".
        with pytest.raises(AwsError):
            AwsIdentityProvider(
                FakeStsSession(response=response)
            ).authenticated_identity()

    def test_a_missing_arn_is_tolerated(self) -> None:
        # The principal is audit metadata, not the gate. Its absence
        # must not fail a scan whose account is known.
        identity = AwsIdentityProvider(
            FakeStsSession(response={"Account": ACCOUNT})
        ).authenticated_identity()
        assert identity.account_id == ACCOUNT
        assert identity.principal is None


# ---------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------


def entra_token(**claims) -> str:
    """A structurally real JWT. Signature is irrelevant — see the adapter."""

    def segment(payload: dict) -> str:
        raw = json.dumps(payload).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = segment({"alg": "RS256", "typ": "JWT"})
    body = segment({"tid": DIRECTORY, "oid": "00000000-obj", "aud": "https://management.azure.com/", **claims})
    return f"{header}.{body}.not-a-real-signature"


class FakeAccessToken:
    def __init__(self, token: str) -> None:
        self.token = token
        self.expires_on = 4102444800


class FakeCredential:
    def __init__(self, *, token: str | None = None, error: Exception | None = None) -> None:
        self._token = token
        self._error = error
        self.scopes: list[tuple[str, ...]] = []

    def get_token(self, *scopes, **kwargs):
        self.scopes.append(scopes)
        if self._error is not None:
            raise self._error
        return FakeAccessToken(self._token) if self._token is not None else None


def azure_provider(credential):
    return AzureIdentityProvider(credential=credential, subscription_id=SUBSCRIPTION)


class TestAzureIdentity:
    def test_it_reads_the_directory_from_the_token(self) -> None:
        # The fix for the audit's §3.2: the authenticated directory now
        # comes from a real token's `tid`, not from a config field that
        # DefaultAzureCredential silently ignores.
        identity = azure_provider(FakeCredential(token=entra_token())).authenticated_identity()
        assert identity.directory_id == DIRECTORY
        assert identity.provider is CloudProvider.AZURE

    def test_it_reports_the_configured_subscription(self) -> None:
        identity = azure_provider(FakeCredential(token=entra_token())).authenticated_identity()
        assert identity.account_id == SUBSCRIPTION

    def test_it_requests_the_management_scope(self) -> None:
        # A token for another audience would authenticate and then fail
        # at the first ARM call.
        credential = FakeCredential(token=entra_token())
        azure_provider(credential).authenticated_identity()
        assert credential.scopes == [(ARM_SCOPE,)]

    def test_it_acquires_a_token_eagerly(self) -> None:
        # DefaultAzureCredential resolves lazily, so before this the
        # first sign of a bad credential appeared deep inside a
        # collector and was attributed to that collector.
        credential = FakeCredential(token=entra_token())
        azure_provider(credential).authenticated_identity()
        assert len(credential.scopes) == 1

    @pytest.mark.parametrize("claim", ["oid", "appid", "sub"])
    def test_the_principal_comes_from_whichever_claim_is_present(self, claim) -> None:
        token = entra_token(**{"oid": None, "appid": None, "sub": None, claim: "principal-1"})
        identity = azure_provider(FakeCredential(token=token)).authenticated_identity()
        assert identity.principal == "principal-1"


class TestAzureIdentityFailsLoudly:
    def test_a_credential_error_raises(self) -> None:
        class ClientAuthenticationError(Exception):
            pass

        with pytest.raises(AzureError):
            azure_provider(
                FakeCredential(error=ClientAuthenticationError("no credential found"))
            ).authenticated_identity()

    def test_a_token_acquisition_failure_raises(self) -> None:
        with pytest.raises(AzureError):
            azure_provider(
                FakeCredential(error=OSError("network unreachable"))
            ).authenticated_identity()

    def test_no_token_raises(self) -> None:
        with pytest.raises(AzureError):
            azure_provider(FakeCredential(token=None)).authenticated_identity()

    @pytest.mark.parametrize(
        "token",
        [
            "not-a-jwt",
            "only.two",
            "a.b.c.d",
            "header.!!!not-base64!!!.sig",
        ],
    )
    def test_an_undecodable_token_raises(self, token) -> None:
        with pytest.raises(AzureError):
            azure_provider(FakeCredential(token=token)).authenticated_identity()

    def test_a_token_without_tid_raises(self) -> None:
        # Without `tid` we cannot say which directory authenticated,
        # which is the only question this adapter exists to answer.
        with pytest.raises(AzureError):
            azure_provider(
                FakeCredential(token=entra_token(tid=None))
            ).authenticated_identity()

    def test_a_blank_tid_raises(self) -> None:
        with pytest.raises(AzureError):
            azure_provider(
                FakeCredential(token=entra_token(tid="   "))
            ).authenticated_identity()


class TestNoTokenMaterialLeaks:
    def test_the_token_never_appears_in_a_decode_error(self) -> None:
        # An access token IS a bearer credential. A decode failure that
        # echoes the bytes it choked on puts one in the logs.
        secret_looking = "header." + "S3CRETTOKENBYTES" + ".sig"
        with pytest.raises(AzureError) as caught:
            azure_provider(FakeCredential(token=secret_looking)).authenticated_identity()
        assert "S3CRETTOKENBYTES" not in str(caught.value)

    def test_the_token_never_appears_in_a_successful_identity(self) -> None:
        identity = azure_provider(
            FakeCredential(token=entra_token())
        ).authenticated_identity()
        rendered = repr(identity)
        assert "not-a-real-signature" not in rendered
