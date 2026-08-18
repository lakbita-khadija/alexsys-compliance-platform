"""IAM user collection (blueprint §6: CURRENT, IAM Users only — IAM
Roles remain FUTURE and are not collected here).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.iam import normalize_iam_account_summary, normalize_iam_user
from infrastructure.cloud.aws.policy_analysis import policy_grants_full_admin
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector


class IamCollector(AwsResourceCollector):
    """Collects every IAM user in the account. All three list operations
    used here (``ListUsers``, ``ListAccessKeys``, ``ListAttachedUserPolicies``)
    are paginated and handled via boto3 paginators.
    """

    resource_type = "IAM users"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("iam")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting IAM users")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        users = [
            user
            for page in client.get_paginator("list_users").paginate()
            for user in page.get("Users", [])
        ]
        return tuple(self._collect_one(client, user, collected_at) for user in users)

    def _collect_one(self, client, user: dict, collected_at) -> NormalizedResource:
        name = user["UserName"]
        access_keys = [
            key
            for page in client.get_paginator("list_access_keys").paginate(UserName=name)
            for key in page.get("AccessKeyMetadata", [])
        ]
        attached_policies = [
            policy
            for page in client.get_paginator("list_attached_user_policies").paginate(UserName=name)
            for policy in page.get("AttachedPolicies", [])
        ]
        policy_names = tuple(policy["PolicyName"] for policy in attached_policies)
        mfa_devices = client.list_mfa_devices(UserName=name).get("MFADevices", [])

        return normalize_iam_user(
            arn=user["Arn"],
            mfa_active=len(mfa_devices) > 0,
            access_key_count=len(access_keys),
            active_access_key_count=sum(1 for key in access_keys if key.get("Status") == "Active"),
            attached_policy_names=policy_names,
            has_full_admin_policy=any(
                self._policy_grants_full_admin(client, policy["PolicyArn"]) for policy in attached_policies
            ),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    @staticmethod
    def _policy_grants_full_admin(client, policy_arn: str) -> bool:
        default_version_id = client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        document = client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)["PolicyVersion"][
            "Document"
        ]
        return policy_grants_full_admin(document)


class IamAccountCollector(AwsResourceCollector):
    """Collects the account-wide IAM settings that don't belong to any
    single user: root account MFA status and the account password
    policy (blueprint §15's account-level checks).

    Emits exactly one resource per scan — there is only ever one such
    resource per AWS account. ``account_id`` must be supplied (from STS,
    by ``AwsCollector``): without it there is no stable ``resource_id``
    to give this resource, so this collector is skipped by
    ``AwsCollector`` when ``account_id`` is unavailable rather than
    inventing a placeholder identity.
    """

    resource_type = "IAM account settings"

    def collect(self) -> tuple[NormalizedResource, ...]:
        if not self._account_id:
            return ()
        client = self._session.client("iam")
        try:
            return (self._collect_one(client),)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting IAM account settings")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect_one(self, client) -> NormalizedResource:
        assert self._account_id is not None  # guaranteed by collect()'s early return above
        summary = client.get_account_summary().get("SummaryMap", {})
        root_mfa_enabled = bool(summary.get("AccountMFAEnabled"))
        policy = self._password_policy(client)

        return normalize_iam_account_summary(
            account_id=self._account_id,
            root_mfa_enabled=root_mfa_enabled,
            has_password_policy=policy is not None,
            password_policy_min_length=(policy or {}).get("MinimumPasswordLength"),
            password_policy_requires_symbols=(policy or {}).get("RequireSymbols"),
            password_policy_requires_numbers=(policy or {}).get("RequireNumbers"),
            password_policy_max_age_days=(policy or {}).get("MaxPasswordAge"),
            password_policy_reuse_prevention=(policy or {}).get("PasswordReusePrevention"),
            tenant_id=self._tenant_id,
            collected_at=self._clock(),
        )

    @staticmethod
    def _password_policy(client) -> dict | None:
        try:
            return client.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if _error_code(exc) == "NoSuchEntity":
                return None
            raise


def _error_code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")
