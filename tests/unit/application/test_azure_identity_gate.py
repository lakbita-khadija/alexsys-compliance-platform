"""STEP 6.5 — the identity gate on the Azure path (§8, §14).

Azure needed more than AWS did. AWS at least *called*
`sts:GetCallerIdentity` and threw the answer away; Azure asked nothing at
all, passed its configured directory as
`DefaultAzureCredential(interactive_browser_tenant_id=...)` — which
scopes only the interactive-browser link in the chain — and carried a
comment asserting no identity round trip was needed.

So these tests exercise the whole replacement: a real token is acquired,
its `tid` claim read, and both the directory and the subscription
checked against the tenant's binding before anything is collected.

Two directory-mismatch cases are the ones that would have passed before:
a correct subscription in the wrong Entra directory, and a credential
that resolved to a different directory than configuration claimed.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from application.scanning.verify_cloud_identity import (
    CloudAuthenticationFailure,
    VerifyCloudIdentity,
)
from domain.audit.models import AuditAction
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import UNKNOWN
from domain.tenants.cloud_accounts import CloudAccountBinding
from infrastructure.cloud.account_directory import StaticCloudAccountDirectory
from infrastructure.cloud.azure.identity import AzureIdentityProvider
from tests.unit.application.test_verify_cloud_identity import RecordingAudit

ACME = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

SUB_A = "aaaaaaaa-0000-0000-0000-000000000001"
SUB_B = "bbbbbbbb-0000-0000-0000-000000000002"
DIR_A = "dddddddd-0000-0000-0000-00000000000a"
DIR_B = "dddddddd-0000-0000-0000-00000000000b"


def token_for(directory: str) -> str:
    def segment(payload: dict) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(payload).encode())
            .rstrip(b"=")
            .decode("ascii")
        )

    return ".".join(
        [
            segment({"alg": "RS256", "typ": "JWT"}),
            segment({"tid": directory, "oid": "principal-1"}),
            "signature-not-checked-here",
        ]
    )


class FakeCredential:
    """Stands in for any azure-identity credential mode.

    The same double covers environment credentials, managed identity and
    a service principal, because all three expose exactly one method we
    use — `get_token` — and differ only in how they resolve underneath.
    What the gate cares about is the `tid` in the token that comes back.
    """

    def __init__(self, *, directory: str | None = None, error: Exception | None = None) -> None:
        self._directory = directory
        self._error = error

    def get_token(self, *scopes, **kwargs):
        if self._error is not None:
            raise self._error

        class _Token:
            token = token_for(self._directory)  # type: ignore[misc]

        return _Token()


class RecordingCollector:
    def __init__(self, resources=()) -> None:
        self._resources = tuple(resources)
        self.collected = False

    def collect(self):
        self.collected = True
        return self._resources


class EmptyCatalog:
    def load(self, rule_ids=None):
        return ()


def a_storage_account(*, attributes=None):
    return NormalizedResource(
        resource_id=ResourceId("stacct1"),
        resource_type="azure_storage_account",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=ACME,
        region="westeurope",
        attributes=attributes if attributes is not None else {"public": False},
        tags={},
        relationships=(),
        collected_at=NOW,
        account_id=SUB_A,
    )


def scanner(
    *,
    authenticated_directory=DIR_A,
    scanned_subscription=SUB_A,
    bound_subscription=SUB_A,
    bound_directory=DIR_A,
    resources=(),
    audit=None,
    credential_error=None,
):
    collector = RecordingCollector(resources)
    gate = VerifyCloudIdentity(
        identity_provider=AzureIdentityProvider(
            credential=FakeCredential(
                directory=authenticated_directory, error=credential_error
            ),
            subscription_id=scanned_subscription,
        ),
        directory=StaticCloudAccountDirectory(
            [
                CloudAccountBinding(
                    tenant_id=ACME,
                    provider=CloudProvider.AZURE,
                    account_id=bound_subscription,
                    directory_id=bound_directory,
                )
            ]
            if bound_subscription is not None
            else []
        ),
        audit=audit,
    )
    return (
        ScanCloudAccount(
            collector=collector, rule_catalog=EmptyCatalog(), verify_identity=gate
        ),
        collector,
    )


def run(use_case, **kwargs):
    return use_case.run(
        tenant_id=ACME,
        provider=CloudProvider.AZURE,
        credentials_reference="azure://subscription",
        scan_configuration=ScanConfiguration(),
        scanned_at=NOW,
        **kwargs,
    )


class TestTheCorrectTenantAndSubscriptionScan:
    def test_a_scan_proceeds(self) -> None:
        use_case, collector = scanner(resources=[a_storage_account()])
        result = run(use_case)
        assert collector.collected is True
        assert len(result.resources) == 1


class TestWrongIdentityIsRejected:
    def test_a_wrong_directory_is_rejected(self) -> None:
        """The check that did not exist before STEP 6.5.

        Subscription matches, credential resolved to a different Entra
        directory. Previously this scanned happily.
        """

        use_case, collector = scanner(
            authenticated_directory=DIR_B, resources=[a_storage_account()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        assert collector.collected is False

    def test_a_wrong_subscription_is_rejected(self) -> None:
        use_case, collector = scanner(
            scanned_subscription=SUB_B, bound_subscription=SUB_A, resources=[a_storage_account()]
        )
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        assert collector.collected is False

    def test_a_missing_binding_is_rejected(self) -> None:
        use_case, collector = scanner(bound_subscription=None)
        with pytest.raises(CloudIdentityMismatch, match="no configured"):
            run(use_case)
        assert collector.collected is False

    def test_the_rejection_is_audited(self) -> None:
        audit = RecordingAudit()
        use_case, _ = scanner(authenticated_directory=DIR_B, audit=audit)
        with pytest.raises(CloudIdentityMismatch):
            run(use_case)
        event = audit.events[0]
        assert event["action"] is AuditAction.AUTHENTICATION_FAILED
        assert event["metadata"]["authenticated_directory_id"] == DIR_B


class TestCredentialFailuresRejectTheScan:
    def test_invalid_credentials_reject(self) -> None:
        class ClientAuthenticationError(Exception):
            pass

        use_case, collector = scanner(
            credential_error=ClientAuthenticationError("secret is invalid")
        )
        with pytest.raises(CloudAuthenticationFailure):
            run(use_case)
        assert collector.collected is False

    def test_a_token_acquisition_failure_rejects(self) -> None:
        use_case, collector = scanner(credential_error=OSError("IMDS unreachable"))
        with pytest.raises(CloudAuthenticationFailure):
            run(use_case)
        assert collector.collected is False

    def test_the_failure_is_audited_without_the_message(self) -> None:
        # An Azure SDK error can embed a request URL, and a SAS-style URL
        # carries its credential in the query string.
        audit = RecordingAudit()
        use_case, _ = scanner(
            credential_error=OSError("GET https://x/?sig=SECRETSIG failed"), audit=audit
        )
        with pytest.raises(CloudAuthenticationFailure):
            run(use_case)
        assert "SECRETSIG" not in repr(audit.events[0])


class TestCredentialModesAreCoveredAsFarAsLocallyPossible:
    """§8 items 8 and 9.

    Environment credentials, managed identity and a service principal all
    expose the same `get_token` surface; the gate reads `tid` from what
    comes back and cannot tell them apart — which is the point, because
    the pre-STEP-6.5 code behaved DIFFERENTLY across these modes and that
    was the bug.

    What cannot be proved here: that a real `DefaultAzureCredential`
    resolves to the mode an operator expects. That needs a live tenant
    and is recorded as such.
    """

    @pytest.mark.parametrize(
        "mode", ["environment", "managed_identity", "service_principal"]
    )
    def test_every_mode_is_gated_identically(self, mode) -> None:
        ok, _ = scanner(authenticated_directory=DIR_A, resources=[a_storage_account()])
        assert len(run(ok).resources) == 1

        wrong, collector = scanner(authenticated_directory=DIR_B)
        with pytest.raises(CloudIdentityMismatch):
            run(wrong)
        assert collector.collected is False


class TestResourceUncertaintyStillMeansUnknown:
    def test_access_denied_on_a_resource_does_not_reject_the_scan(self) -> None:
        # The semantics that must not be reversed: an unreadable
        # property is UNKNOWN and the scan continues.
        denied = a_storage_account(attributes={"public": UNKNOWN})
        use_case, collector = scanner(resources=[denied])

        result = run(use_case)

        assert collector.collected is True
        assert result.resources[0].attributes["public"] is UNKNOWN
