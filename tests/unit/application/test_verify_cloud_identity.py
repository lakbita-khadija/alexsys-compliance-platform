"""STEP 6.5 — the pre-collection authentication gate.

Two things are under test and they are equally important.

**The gate.** A scan must not collect from an account the tenant is not
bound to. The ordering matters as much as the check: it runs *before*
collection, because once resources exist in memory tagged with the
requesting tenant, the misattribution has already happened and every
later control is protecting the wrong data.

**The audit trail.** `AUTHENTICATION_FAILED` was declared in Phase 5 and
emitted by nothing — a security event vocabulary with no callers. These
tests pin the emission, its metadata, and — the part that would actually
hurt — that no credential material rides along.
"""

from __future__ import annotations

import pytest

from application.ports.audit import AuditRecorder
from application.scanning.verify_cloud_identity import (
    CloudAuthenticationFailure,
    VerifyCloudIdentity,
)
from domain.audit.models import AuditAction
from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import AuthenticatedCloudIdentity, CloudAccountBinding
from infrastructure.cloud.account_directory import StaticCloudAccountDirectory

ACME = TenantId("acme")
GLOBEX = TenantId("globex")
AWS_A = "111111111111"
AWS_B = "222222222222"
CORRELATION = "corr-abc-123"


class RecordingAudit(AuditRecorder):
    """Captures calls verbatim, so tests can assert on exact payloads."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, **kwargs) -> None:  # noqa: ANN003 - mirrors the port
        self.events.append(kwargs)


class StubIdentity:
    def __init__(self, *, identity=None, error: Exception | None = None) -> None:
        self._identity = identity
        self._error = error
        self.calls = 0

    def authenticated_identity(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._identity


def aws_identity(account=AWS_A):
    return AuthenticatedCloudIdentity(
        provider=CloudProvider.AWS,
        account_id=account,
        principal=f"arn:aws:iam::{account}:role/scanner",
    )


def directory(*bindings):
    return StaticCloudAccountDirectory(bindings)


def binding(tenant=ACME, account=AWS_A):
    return CloudAccountBinding(
        tenant_id=tenant, provider=CloudProvider.AWS, account_id=account
    )


def gate(*, identity=None, error=None, bindings=(), audit=None):
    return VerifyCloudIdentity(
        identity_provider=StubIdentity(identity=identity, error=error),
        directory=directory(*bindings),
        audit=audit,
    )


class TestThePositivePath:
    def test_a_bound_account_is_authorized(self) -> None:
        result = gate(identity=aws_identity(), bindings=[binding()]).execute(
            tenant_id=ACME, provider=CloudProvider.AWS
        )
        assert result.account_id == AWS_A

    def test_success_records_no_audit_event(self) -> None:
        # The audit trail records the failures. Recording every
        # successful authentication would bury them under volume, which
        # is the same reasoning `AuditAction` uses to exclude reads.
        audit = RecordingAudit()
        gate(identity=aws_identity(), bindings=[binding()], audit=audit).execute(
            tenant_id=ACME, provider=CloudProvider.AWS
        )
        assert audit.events == []

    def test_the_provider_is_actually_consulted(self) -> None:
        # A gate that never asks the provider is comparing configuration
        # against itself.
        stub = StubIdentity(identity=aws_identity())
        VerifyCloudIdentity(
            identity_provider=stub, directory=directory(binding())
        ).execute(tenant_id=ACME, provider=CloudProvider.AWS)
        assert stub.calls == 1


class TestTheNegativePaths:
    def test_a_wrong_account_is_rejected(self) -> None:
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

    def test_a_missing_binding_is_rejected(self) -> None:
        with pytest.raises(CloudIdentityMismatch, match="no configured"):
            gate(identity=aws_identity(), bindings=[]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

    def test_tenant_a_cannot_use_tenant_b_binding(self) -> None:
        with pytest.raises(CloudIdentityMismatch):
            gate(
                identity=aws_identity(AWS_B),
                bindings=[binding(ACME, AWS_A), binding(GLOBEX, AWS_B)],
            ).execute(tenant_id=ACME, provider=CloudProvider.AWS)

    @pytest.mark.parametrize(
        "error",
        [
            RuntimeError("no credentials"),
            OSError("network unreachable"),
            ValueError("malformed STS response"),
        ],
    )
    def test_any_identity_failure_rejects(self, error) -> None:
        # Missing, invalid, expired, unreachable — all one conclusion:
        # we do not know which account this is, so we must not collect.
        with pytest.raises(CloudAuthenticationFailure):
            gate(error=error, bindings=[binding()]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

    def test_an_identity_failure_is_still_a_mismatch_subclass(self) -> None:
        # So a caller that wants to abort on "any identity problem" can
        # catch one exception, while a caller that triages them
        # separately still can.
        with pytest.raises(CloudIdentityMismatch):
            gate(error=RuntimeError("boom"), bindings=[binding()]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

    def test_the_original_cause_is_preserved(self) -> None:
        original = RuntimeError("underlying detail")
        with pytest.raises(CloudAuthenticationFailure) as caught:
            gate(error=original, bindings=[binding()]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert caught.value.__cause__ is original


class TestAuditEmission:
    """`AUTHENTICATION_FAILED` finally has a caller."""

    def test_a_mismatch_emits_authentication_failed(self) -> None:
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert [e["action"] for e in audit.events] == [AuditAction.AUTHENTICATION_FAILED]

    def test_an_identity_failure_emits_it_too(self) -> None:
        audit = RecordingAudit()
        with pytest.raises(CloudAuthenticationFailure):
            gate(error=RuntimeError("boom"), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert audit.events[0]["action"] is AuditAction.AUTHENTICATION_FAILED

    def test_the_two_failures_are_distinguishable(self) -> None:
        # An operator triages them differently: a mismatch is a
        # configuration error, an identity failure is a credential
        # problem.
        mismatch, unavailable = RecordingAudit(), RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=mismatch).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        with pytest.raises(CloudAuthenticationFailure):
            gate(error=RuntimeError("x"), bindings=[binding()], audit=unavailable).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert mismatch.events[0]["metadata"]["reason"] == "account_not_bound_to_tenant"
        assert unavailable.events[0]["metadata"]["reason"] == "identity_unavailable"

    def test_the_event_carries_the_tenant(self) -> None:
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert audit.events[0]["tenant_id"] == ACME

    def test_the_event_carries_the_correlation_id(self) -> None:
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS, correlation_id=CORRELATION
            )
        assert audit.events[0]["correlation_id"] == CORRELATION

    def test_the_event_names_the_account_we_authenticated_as(self) -> None:
        # The one fact an operator needs to fix it. Not a secret: an AWS
        # account id appears in every ARN.
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert audit.events[0]["metadata"]["authenticated_account_id"] == AWS_B

    def test_the_actor_is_the_system(self) -> None:
        # A scheduled scan has no human behind it.
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert audit.events[0]["actor_kind"] == "system"

    def test_it_works_without_an_audit_recorder(self) -> None:
        # Audit is optional wiring; its absence must not change the gate.
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=None).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )


class TestNoSecretsInTheAuditTrail:
    def test_the_exception_type_is_recorded_never_its_message(self) -> None:
        """The detail that could leak.

        SDK exception messages can embed request URLs, and an Azure
        SAS-style URL carries its credential in the query string. So the
        gate records the exception's TYPE and discards its text.
        """

        audit = RecordingAudit()
        leaky = RuntimeError(
            "failed calling https://acct.blob.core.windows.net/?sig=SECRETSIGNATURE"
        )
        with pytest.raises(CloudAuthenticationFailure):
            gate(error=leaky, bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

        serialized = repr(audit.events[0])
        assert "SECRETSIGNATURE" not in serialized
        assert "sig=" not in serialized
        assert audit.events[0]["metadata"]["detail"] == "RuntimeError"

    def test_the_raised_error_does_not_echo_the_message_either(self) -> None:
        leaky = RuntimeError("token=BEARERVALUE123")
        with pytest.raises(CloudAuthenticationFailure) as caught:
            gate(error=leaky, bindings=[binding()]).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )
        assert "BEARERVALUE123" not in str(caught.value)

    def test_no_credential_shaped_key_is_ever_recorded(self) -> None:
        # `AuditEvent` rejects credential-shaped metadata keys outright
        # rather than redacting them, so a mistake here fails loudly.
        # This asserts we never hand it one in the first place.
        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS
            )

        from infrastructure.persistence.postgres.mappers.redaction import is_secret_key

        assert [k for k in audit.events[0]["metadata"] if is_secret_key(k)] == []

    def test_the_recorded_metadata_survives_a_real_audit_event(self) -> None:
        """End to end through the constructor that enforces the rule.

        The gate building safe-looking metadata is only half the
        guarantee; this proves `AuditEvent` accepts it, so the trail is
        actually written rather than rejected at the boundary.
        """

        from datetime import datetime, timezone

        from domain.audit.models import AuditActor, AuditEvent

        audit = RecordingAudit()
        with pytest.raises(CloudIdentityMismatch):
            gate(identity=aws_identity(AWS_B), bindings=[binding()], audit=audit).execute(
                tenant_id=ACME, provider=CloudProvider.AWS, correlation_id=CORRELATION
            )

        captured = audit.events[0]
        event = AuditEvent(
            event_id="evt-1",
            tenant_id=captured["tenant_id"],
            actor=AuditActor(subject=captured["actor_subject"], kind=captured["actor_kind"]),
            action=captured["action"],
            occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            resource=captured["resource"],
            resource_type=captured["resource_type"],
            correlation_id=captured["correlation_id"],
            metadata=dict(captured["metadata"]),
        )
        assert event.action is AuditAction.AUTHENTICATION_FAILED
        assert event.correlation_id == CORRELATION
