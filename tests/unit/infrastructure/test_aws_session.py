from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from infrastructure.cloud.aws.credentials import AwsCredentialConfig
from infrastructure.cloud.aws.errors import AwsPermissionError
from infrastructure.cloud.aws.session import AwsSessionFactory


class TestAwsCredentialConfig:
    def test_valid_config_with_defaults(self) -> None:
        config = AwsCredentialConfig(region="us-east-1")
        assert config.profile is None
        assert config.role_arn is None

    def test_blank_region_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            AwsCredentialConfig(region="   ")

    def test_config_never_carries_raw_access_keys(self) -> None:
        # AwsCredentialConfig has no access-key/secret fields at all —
        # this test documents that as an architectural guarantee, not
        # just an omission.
        import dataclasses

        field_names = {f.name for f in dataclasses.fields(AwsCredentialConfig)}
        assert "aws_access_key_id" not in field_names
        assert "aws_secret_access_key" not in field_names


class TestAwsSessionFactoryDefaultChain:
    @patch("infrastructure.cloud.aws.session.boto3.Session")
    def test_uses_default_credential_chain_when_no_role_arn(self, mock_session_cls) -> None:
        config = AwsCredentialConfig(region="us-east-1", profile="my-profile")
        AwsSessionFactory().create(config)
        mock_session_cls.assert_called_once_with(profile_name="my-profile", region_name="us-east-1")

    @patch("infrastructure.cloud.aws.session.boto3.Session")
    def test_profile_is_optional(self, mock_session_cls) -> None:
        config = AwsCredentialConfig(region="us-east-1")
        AwsSessionFactory().create(config)
        mock_session_cls.assert_called_once_with(profile_name=None, region_name="us-east-1")


class TestAwsSessionFactoryRoleAssumption:
    @patch("infrastructure.cloud.aws.session.boto3.Session")
    def test_assumes_role_and_builds_a_session_from_temporary_credentials(self, mock_session_cls) -> None:
        base_session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA-TEMP",
                "SecretAccessKey": "temp-secret",
                "SessionToken": "temp-token",
            }
        }
        base_session.client.return_value = sts_client
        assumed_session = MagicMock()
        mock_session_cls.side_effect = [base_session, assumed_session]

        config = AwsCredentialConfig(region="us-east-1", role_arn="arn:aws:iam::123456789012:role/scan-role")
        result = AwsSessionFactory().create(config)

        sts_client.assume_role.assert_called_once()
        call_kwargs = sts_client.assume_role.call_args.kwargs
        assert call_kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/scan-role"
        assert mock_session_cls.call_count == 2
        second_call_kwargs = mock_session_cls.call_args_list[1].kwargs
        assert second_call_kwargs["aws_access_key_id"] == "AKIA-TEMP"
        assert second_call_kwargs["aws_secret_access_key"] == "temp-secret"
        assert second_call_kwargs["aws_session_token"] == "temp-token"
        assert result is assumed_session

    @patch("infrastructure.cloud.aws.session.boto3.Session")
    def test_role_assumption_failure_is_translated(self, mock_session_cls) -> None:
        base_session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, "AssumeRole"
        )
        base_session.client.return_value = sts_client
        mock_session_cls.return_value = base_session

        config = AwsCredentialConfig(region="us-east-1", role_arn="arn:aws:iam::123456789012:role/scan-role")
        with pytest.raises(AwsPermissionError):
            AwsSessionFactory().create(config)

    @patch("infrastructure.cloud.aws.session.boto3.Session")
    def test_temporary_credentials_never_appear_in_repr_of_config(self, mock_session_cls) -> None:
        # The config itself never carries secrets, so its repr can't leak any.
        config = AwsCredentialConfig(region="us-east-1", role_arn="arn:aws:iam::123456789012:role/scan-role")
        assert "AKIA" not in repr(config)
        assert "secret" not in repr(config).lower()
