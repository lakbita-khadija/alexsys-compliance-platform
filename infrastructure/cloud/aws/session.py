"""``AwsSessionFactory`` — the one place a ``boto3.Session`` is
constructed.

Isolating this in a single small class (rather than letting every
resource collector build its own session) is what makes the collectors
unit-testable without AWS credentials: tests construct a collector with
a fake/mocked ``boto3.client``, never going through this factory at
all. Production code goes through here exactly once per scan.
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from infrastructure.cloud.aws.credentials import AwsCredentialConfig
from infrastructure.cloud.aws.errors import translate_client_error

_ASSUME_ROLE_SESSION_NAME = "complianceiq-scan"


class AwsSessionFactory:
    """Builds a ``boto3.Session`` from an ``AwsCredentialConfig``.

    Never constructs a session from raw access keys (blueprint Phase 3
    brief §9/§10) — only boto3's own default credential chain (via an
    optional named profile) and, optionally, STS role assumption on top
    of it.
    """

    def create(self, config: AwsCredentialConfig) -> boto3.Session:
        base_session = boto3.Session(profile_name=config.profile, region_name=config.region)

        if config.role_arn is None:
            return base_session

        return self._assume_role(base_session, config)

    @staticmethod
    def _assume_role(base_session: boto3.Session, config: AwsCredentialConfig) -> boto3.Session:
        role_arn = config.role_arn
        if role_arn is None:  # pragma: no cover - guarded by the caller
            raise ValueError("_assume_role requires a role_arn")

        sts_client = base_session.client("sts")
        # Built conditionally rather than passing ExternalId=None: botocore
        # validates the parameter's type and rejects an explicit None,
        # so an absent external id must be an absent key.
        parameters: dict[str, str] = {
            "RoleArn": role_arn,
            "RoleSessionName": _ASSUME_ROLE_SESSION_NAME,
        }
        if config.external_id is not None:
            parameters["ExternalId"] = config.external_id

        try:
            response = sts_client.assume_role(**parameters)
        except ClientError as exc:
            # The context names the role ARN and never the external id.
            # An AccessDenied from a wrong external id must not echo the
            # value that was tried.
            raise translate_client_error(exc, context=f"assuming role {config.role_arn}") from exc

        temporary_credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=temporary_credentials["AccessKeyId"],
            aws_secret_access_key=temporary_credentials["SecretAccessKey"],
            aws_session_token=temporary_credentials["SessionToken"],
            region_name=config.region,
        )
