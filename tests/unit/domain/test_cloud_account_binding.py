"""STEP 6.5 — the tenant ↔ cloud account binding, in the domain.

The rule these tests exist to protect: **a scan may only collect from an
account the tenant is declared to own.** Before this, `Tenant` was
`(id, name)`, nothing recorded ownership, and the scanner used the
authenticated account id as a label rather than a gate — so pointing a
tenant's scan at the wrong credentials handed it another organization's
entire estate, correctly tenant-tagged.

The tests that matter most here are the ones asserting the control
**fails closed**. A binding check that allows a scan when no binding is
configured looks exactly like a working control and is worthless.
"""

from __future__ import annotations

import pytest

from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch, InvalidCloudAccountBinding
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import (
    AuthenticatedCloudIdentity,
    CloudAccountBinding,
    verify_cloud_identity,
)

ACME = TenantId("acme")
GLOBEX = TenantId("globex")

AWS_A = "111111111111"
AWS_B = "222222222222"
SUB_A = "aaaaaaaa-0000-0000-0000-000000000001"
DIR_A = "dddddddd-0000-0000-0000-00000000000a"
DIR_B = "dddddddd-0000-0000-0000-00000000000b"


def aws_binding(tenant=ACME, account=AWS_A):
    return CloudAccountBinding(
        tenant_id=tenant, provider=CloudProvider.AWS, account_id=account
    )


def azure_binding(tenant=ACME, account=SUB_A, directory=DIR_A):
    return CloudAccountBinding(
        tenant_id=tenant,
        provider=CloudProvider.AZURE,
        account_id=account,
        directory_id=directory,
    )


def aws_identity(account=AWS_A):
    return AuthenticatedCloudIdentity(
        provider=CloudProvider.AWS,
        account_id=account,
        principal=f"arn:aws:iam::{account}:role/scanner",
    )


def azure_identity(account=SUB_A, directory=DIR_A):
    return AuthenticatedCloudIdentity(
        provider=CloudProvider.AZURE, account_id=account, directory_id=directory
    )


class TestBindingConstruction:
    def test_a_valid_aws_binding(self) -> None:
        assert aws_binding().account_id == AWS_A

    def test_a_valid_azure_binding(self) -> None:
        assert azure_binding().directory_id == DIR_A

    @pytest.mark.parametrize("account", ["", "   ", None, 12345])
    def test_a_blank_or_non_string_account_is_rejected(self, account) -> None:
        with pytest.raises(InvalidCloudAccountBinding):
            CloudAccountBinding(
                tenant_id=ACME, provider=CloudProvider.AWS, account_id=account
            )

    def test_a_non_provider_is_rejected(self) -> None:
        with pytest.raises(InvalidCloudAccountBinding):
            CloudAccountBinding(tenant_id=ACME, provider="aws", account_id=AWS_A)

    def test_a_blank_directory_is_rejected(self) -> None:
        with pytest.raises(InvalidCloudAccountBinding):
            CloudAccountBinding(
                tenant_id=ACME,
                provider=CloudProvider.AZURE,
                account_id=SUB_A,
                directory_id="  ",
            )

    def test_an_azure_binding_without_a_directory_is_rejected(self) -> None:
        """The binding must be able to answer the question it exists for.

        A subscription id alone cannot establish which Entra directory
        authenticated — and a subscription can be moved between
        directories. Allowing the binding would create a check that
        passes while the actual hole (§3.2 of the audit) stays open.
        """

        with pytest.raises(InvalidCloudAccountBinding, match="directory"):
            CloudAccountBinding(
                tenant_id=ACME, provider=CloudProvider.AZURE, account_id=SUB_A
            )

    def test_aws_needs_no_directory(self) -> None:
        # AWS has no second identity scope; requiring one would be
        # inventing a concept the provider does not have.
        assert aws_binding().directory_id is None


class TestTheHappyPath:
    def test_a_bound_aws_account_is_authorized(self) -> None:
        binding = verify_cloud_identity(
            tenant_id=ACME, actual=aws_identity(), bindings=[aws_binding()]
        )
        assert binding.account_id == AWS_A

    def test_a_bound_azure_subscription_is_authorized(self) -> None:
        binding = verify_cloud_identity(
            tenant_id=ACME, actual=azure_identity(), bindings=[azure_binding()]
        )
        assert binding.directory_id == DIR_A

    def test_a_tenant_may_own_several_accounts(self) -> None:
        bindings = [aws_binding(), aws_binding(account=AWS_B)]
        assert verify_cloud_identity(
            tenant_id=ACME, actual=aws_identity(AWS_B), bindings=bindings
        ).account_id == AWS_B

    def test_bindings_for_other_tenants_are_ignored_not_honoured(self) -> None:
        # globex's binding for AWS_B must not authorize acme.
        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=ACME,
                actual=aws_identity(AWS_B),
                bindings=[aws_binding(), aws_binding(tenant=GLOBEX, account=AWS_B)],
            )


class TestItFailsClosed:
    """The tests that decide whether this control is real."""

    def test_no_bindings_at_all_rejects(self) -> None:
        # An empty allow-list means "nothing permitted". Reading it as
        # "no restriction" would make the mechanism fail open, and a
        # control that fails open on missing configuration is worse than
        # none because it looks like one.
        with pytest.raises(CloudIdentityMismatch, match="no configured"):
            verify_cloud_identity(tenant_id=ACME, actual=aws_identity(), bindings=[])

    def test_a_binding_for_another_provider_does_not_authorize(self) -> None:
        with pytest.raises(CloudIdentityMismatch, match="no configured"):
            verify_cloud_identity(
                tenant_id=ACME, actual=aws_identity(), bindings=[azure_binding()]
            )

    def test_a_wrong_aws_account_rejects(self) -> None:
        with pytest.raises(CloudIdentityMismatch, match=AWS_B):
            verify_cloud_identity(
                tenant_id=ACME, actual=aws_identity(AWS_B), bindings=[aws_binding()]
            )

    def test_a_wrong_azure_subscription_rejects(self) -> None:
        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=ACME,
                actual=azure_identity(account="some-other-subscription"),
                bindings=[azure_binding()],
            )

    def test_the_right_subscription_in_the_wrong_directory_rejects(self) -> None:
        """The check §3.2 of the audit found missing.

        Subscription equality alone does not establish that the expected
        organization authenticated — a subscription can be transferred
        between Entra directories.
        """

        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=ACME,
                actual=azure_identity(directory=DIR_B),
                bindings=[azure_binding()],
            )

    def test_an_empty_account_id_matches_nothing(self) -> None:
        # Guards the adapter contract: an identity provider that could
        # not read the account must raise, not return "". If one ever
        # returns a blank, this must still refuse rather than match.
        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=ACME,
                actual=AuthenticatedCloudIdentity(
                    provider=CloudProvider.AWS, account_id=""
                ),
                bindings=[aws_binding()],
            )


class TestCrossTenantIsolation:
    def test_tenant_a_cannot_use_tenant_b_binding(self) -> None:
        # The scenario the whole binding exists for: acme authenticates
        # into globex's account. Both tenants are configured; acme is
        # still refused.
        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=ACME,
                actual=aws_identity(AWS_B),
                bindings=[aws_binding(ACME, AWS_A), aws_binding(GLOBEX, AWS_B)],
            )

    def test_the_same_account_bound_to_two_tenants_is_honoured_per_tenant(self) -> None:
        # Sharing an account across tenants is unusual but not
        # forbidden — an MSP scanning on behalf of a subsidiary. What
        # matters is that it requires an EXPLICIT binding for each; it
        # never happens implicitly.
        shared = [aws_binding(ACME, AWS_A), aws_binding(GLOBEX, AWS_A)]
        assert verify_cloud_identity(
            tenant_id=ACME, actual=aws_identity(), bindings=shared
        ).tenant_id == ACME
        assert verify_cloud_identity(
            tenant_id=GLOBEX, actual=aws_identity(), bindings=shared
        ).tenant_id == GLOBEX

    def test_without_an_explicit_second_binding_the_account_is_not_shared(self) -> None:
        with pytest.raises(CloudIdentityMismatch):
            verify_cloud_identity(
                tenant_id=GLOBEX, actual=aws_identity(), bindings=[aws_binding(ACME, AWS_A)]
            )


class TestTheErrorIsUsefulAndSafe:
    def test_it_names_the_expected_and_actual_accounts(self) -> None:
        # An operator has to be able to fix this from the message. Both
        # values are account identifiers, not secrets: an AWS account id
        # appears in every ARN.
        with pytest.raises(CloudIdentityMismatch) as caught:
            verify_cloud_identity(
                tenant_id=ACME, actual=aws_identity(AWS_B), bindings=[aws_binding()]
            )
        message = str(caught.value)
        assert AWS_A in message and AWS_B in message

    def test_it_is_not_a_tenant_isolation_violation(self) -> None:
        # Different failure, different remediation. Nothing has crossed a
        # tenant boundary — we have not collected anything yet.
        from domain.shared.errors import TenantIsolationViolation

        with pytest.raises(CloudIdentityMismatch) as caught:
            verify_cloud_identity(tenant_id=ACME, actual=aws_identity(), bindings=[])
        assert not isinstance(caught.value, TenantIsolationViolation)
