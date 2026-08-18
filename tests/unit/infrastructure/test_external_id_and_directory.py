"""STEP 6.5 — AssumeRole ExternalId, and the account directory.

**ExternalId** closes P1 #6 from the audit. It is the standard defence
against the confused-deputy problem for a SaaS scanner: a customer's
cross-account role carries an `sts:ExternalId` condition, so knowing the
role ARN — which is not secret and is visible in their own console — is
not enough for another customer of the same vendor to assume it. Without
the field a customer could not configure that protection even if they
wanted to.

**The directory** supplies the expectation side of the identity gate. Its
most important property is the failure direction: an unconfigured
deployment must scan *nothing*, not everything.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from domain.shared.enums import CloudProvider
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import CloudAccountBinding
from infrastructure.cloud.account_directory import (
    ENV_VAR,
    EnvCloudAccountDirectory,
    StaticCloudAccountDirectory,
)
from infrastructure.cloud.aws.credentials import AwsCredentialConfig
from infrastructure.cloud.aws.session import AwsSessionFactory

ACME = TenantId("acme")
GLOBEX = TenantId("globex")
ROLE = "arn:aws:iam::111111111111:role/complianceiq-scanner"
EXTERNAL_ID = "acme-7f3c9a12"

_CREDENTIALS = {
    "Credentials": {
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
    }
}


def assume_role_call(config: AwsCredentialConfig) -> dict:
    """Run the factory against a mocked boto3 and return the STS kwargs."""

    with mock.patch("infrastructure.cloud.aws.session.boto3.Session") as session_cls:
        sts = session_cls.return_value.client.return_value
        sts.assume_role.return_value = _CREDENTIALS
        AwsSessionFactory().create(config)
        return sts.assume_role.call_args.kwargs


class TestExternalIdConfiguration:
    def test_it_defaults_to_absent(self) -> None:
        assert AwsCredentialConfig(region="us-east-1").external_id is None

    def test_it_is_accepted_alongside_a_role(self) -> None:
        config = AwsCredentialConfig(
            region="us-east-1", role_arn=ROLE, external_id=EXTERNAL_ID
        )
        assert config.external_id == EXTERNAL_ID

    @pytest.mark.parametrize("value", ["", "   "])
    def test_a_blank_external_id_is_rejected(self, value) -> None:
        with pytest.raises(ValueError, match="external_id"):
            AwsCredentialConfig(region="us-east-1", role_arn=ROLE, external_id=value)

    def test_an_external_id_without_a_role_is_rejected(self) -> None:
        """A silent no-op is worse than an error.

        STS consults ExternalId during AssumeRole and nowhere else, so
        this configuration would leave an operator believing a control
        is active when nothing consults it.
        """

        with pytest.raises(ValueError, match="only meaningful with role_arn"):
            AwsCredentialConfig(region="us-east-1", external_id=EXTERNAL_ID)


class TestExternalIdIsSentToSts:
    def test_it_is_passed_when_configured(self) -> None:
        kwargs = assume_role_call(
            AwsCredentialConfig(region="us-east-1", role_arn=ROLE, external_id=EXTERNAL_ID)
        )
        assert kwargs["ExternalId"] == EXTERNAL_ID
        assert kwargs["RoleArn"] == ROLE

    def test_the_key_is_absent_when_unconfigured(self) -> None:
        # Not `ExternalId=None`: botocore validates parameter types and
        # rejects an explicit None, so absence must mean an absent key.
        kwargs = assume_role_call(AwsCredentialConfig(region="us-east-1", role_arn=ROLE))
        assert "ExternalId" not in kwargs

    def test_existing_behaviour_is_unchanged_without_one(self) -> None:
        kwargs = assume_role_call(AwsCredentialConfig(region="us-east-1", role_arn=ROLE))
        assert set(kwargs) == {"RoleArn", "RoleSessionName"}


class TestExternalIdIsNotDisclosed:
    def test_it_is_absent_from_the_config_repr(self) -> None:
        # A config object that prints it ends up in a traceback, then a
        # log line, then a support ticket.
        config = AwsCredentialConfig(
            region="us-east-1", role_arn=ROLE, external_id=EXTERNAL_ID
        )
        assert EXTERNAL_ID not in repr(config)

    def test_it_is_absent_from_an_assume_role_failure(self) -> None:
        from botocore.exceptions import ClientError

        from infrastructure.cloud.aws.errors import AwsError

        denied = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole"
        )
        config = AwsCredentialConfig(
            region="us-east-1", role_arn=ROLE, external_id=EXTERNAL_ID
        )

        with mock.patch("infrastructure.cloud.aws.session.boto3.Session") as session_cls:
            session_cls.return_value.client.return_value.assume_role.side_effect = denied
            with pytest.raises(AwsError) as caught:
                AwsSessionFactory().create(config)

        # A wrong external id produces AccessDenied. The error must not
        # echo the value that was tried.
        assert EXTERNAL_ID not in str(caught.value)

    def test_two_tenants_cannot_share_one_external_id_by_accident(self) -> None:
        # Nothing global holds it: it travels on the per-scan config, so
        # one tenant's value is structurally unavailable to another's
        # session construction.
        acme = AwsCredentialConfig(region="us-east-1", role_arn=ROLE, external_id="acme-1")
        globex = AwsCredentialConfig(region="us-east-1", role_arn=ROLE, external_id="globex-1")
        assert assume_role_call(acme)["ExternalId"] == "acme-1"
        assert assume_role_call(globex)["ExternalId"] == "globex-1"


class TestStaticDirectory:
    def test_it_returns_only_the_matching_tenant(self) -> None:
        directory = StaticCloudAccountDirectory(
            [
                CloudAccountBinding(ACME, CloudProvider.AWS, "111111111111"),
                CloudAccountBinding(GLOBEX, CloudProvider.AWS, "222222222222"),
            ]
        )
        result = directory.bindings_for(tenant_id=ACME, provider=CloudProvider.AWS)
        assert [b.account_id for b in result] == ["111111111111"]

    def test_it_filters_by_provider(self) -> None:
        directory = StaticCloudAccountDirectory(
            [
                CloudAccountBinding(ACME, CloudProvider.AWS, "111111111111"),
                CloudAccountBinding(ACME, CloudProvider.AZURE, "sub-1", "dir-1"),
            ]
        )
        assert (
            directory.bindings_for(tenant_id=ACME, provider=CloudProvider.AZURE)[0].account_id
            == "sub-1"
        )

    def test_an_unknown_tenant_gets_nothing(self) -> None:
        directory = StaticCloudAccountDirectory(
            [CloudAccountBinding(ACME, CloudProvider.AWS, "111111111111")]
        )
        assert directory.bindings_for(tenant_id=GLOBEX, provider=CloudProvider.AWS) == ()


class TestEnvDirectory:
    def test_it_parses_bindings(self) -> None:
        raw = json.dumps(
            [
                {"tenant_id": "acme", "provider": "aws", "account_id": "111111111111"},
                {
                    "tenant_id": "acme",
                    "provider": "azure",
                    "account_id": "sub-1",
                    "directory_id": "dir-1",
                },
            ]
        )
        directory = EnvCloudAccountDirectory(raw)
        assert directory.bindings_for(tenant_id=ACME, provider=CloudProvider.AWS)[0].account_id == "111111111111"
        assert directory.bindings_for(tenant_id=ACME, provider=CloudProvider.AZURE)[0].directory_id == "dir-1"

    def test_an_unset_variable_permits_nothing(self) -> None:
        """The failure direction that decides whether this is a control.

        A deployment that forgot to configure bindings must refuse to
        scan, not scan whatever it happens to authenticate as.
        """

        assert EnvCloudAccountDirectory("").bindings_for(
            tenant_id=ACME, provider=CloudProvider.AWS
        ) == ()

    def test_it_reads_the_environment_when_no_argument_is_given(self) -> None:
        raw = json.dumps(
            [{"tenant_id": "acme", "provider": "aws", "account_id": "111111111111"}]
        )
        with mock.patch.dict("os.environ", {ENV_VAR: raw}):
            directory = EnvCloudAccountDirectory()
        assert len(directory.bindings_for(tenant_id=ACME, provider=CloudProvider.AWS)) == 1

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("{not json", "not valid JSON"),
            ('{"tenant_id": "acme"}', "must be a JSON array"),
            ('[["acme"]]', "must be an object"),
            ('[{"provider": "aws", "account_id": "1"}]', "tenant_id"),
            ('[{"tenant_id": "a", "account_id": "1"}]', "provider"),
            ('[{"tenant_id": "a", "provider": "aws"}]', "account_id"),
            ('[{"tenant_id": "a", "provider": "gcp", "account_id": "1"}]', "gcp"),
        ],
    )
    def test_malformed_configuration_is_rejected_at_startup(self, raw, expected) -> None:
        # At startup rather than at scan time: an operator finds out when
        # they deploy, not when the first scan of the night fails.
        with pytest.raises(ValueError, match=expected):
            EnvCloudAccountDirectory(raw)

    def test_an_azure_binding_without_a_directory_is_rejected(self) -> None:
        raw = json.dumps([{"tenant_id": "acme", "provider": "azure", "account_id": "sub-1"}])
        with pytest.raises(Exception, match="directory"):
            EnvCloudAccountDirectory(raw)

    def test_parsing_is_deterministic(self) -> None:
        # Two processes reading the same configuration hold it in the
        # same order, matching the codebase's sorting discipline.
        entries = [
            {"tenant_id": "zeta", "provider": "aws", "account_id": "999999999999"},
            {"tenant_id": "acme", "provider": "aws", "account_id": "111111111111"},
        ]
        forward = EnvCloudAccountDirectory(json.dumps(entries))._bindings
        backward = EnvCloudAccountDirectory(json.dumps(list(reversed(entries))))._bindings
        assert forward == backward
