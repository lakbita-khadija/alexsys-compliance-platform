"""AWS authenticated identity, via ``sts:GetCallerIdentity`` (STEP 6.5).

`sts:GetCallerIdentity` was already being called before this module
existed — in `AwsCollector._resolve_account_id`, wrapped in a bare
`except Exception` that returned `None` on any failure. That is the right
behaviour for its purpose there: the account id is an additive *label*
on collected resources, and a denied STS call should degrade the label
rather than abort the scan.

This module answers a different question with the same API call, and
therefore handles failure the opposite way. Here the account id is the
**gate**: not knowing which account we authenticated to is a reason to
refuse to collect, not a reason to proceed with a null field. The two
call sites coexist deliberately and the difference is the point —
`_resolve_account_id` may return `None`, this must raise.

Notably `GetCallerIdentity` requires no IAM permission at all: it cannot
be denied by policy, so a failure here is a genuine credential or
connectivity problem rather than an under-privileged role.
"""

from __future__ import annotations

import boto3

from domain.shared.enums import CloudProvider
from domain.tenants.cloud_accounts import AuthenticatedCloudIdentity
from infrastructure.cloud.aws.errors import translate_client_error


class AwsIdentityProvider:
    """Ask STS who this session is. Implements ``CloudIdentityProvider``."""

    def __init__(self, session: boto3.Session) -> None:
        self._session = session

    def authenticated_identity(self) -> AuthenticatedCloudIdentity:
        try:
            response = self._session.client("sts").get_caller_identity()
        except Exception as exc:  # noqa: BLE001 - see below
            # Deliberately broad, and deliberately re-raised rather than
            # swallowed. NoCredentialsError, EndpointConnectionError and
            # ClientError are three unrelated types with one meaning
            # here: we cannot establish which account this is.
            raise translate_client_error(exc, context="verifying the AWS caller identity") from exc

        account_id = response.get("Account") if isinstance(response, dict) else None
        if not isinstance(account_id, str) or not account_id.strip():
            # A response we cannot parse is not an identity. Accepting a
            # missing Account here would hand `verify_cloud_identity` an
            # empty string to compare, and an empty string matches
            # nothing — so the gate would appear to work while actually
            # failing for the wrong reason.
            raise translate_client_error(
                ValueError("GetCallerIdentity returned no Account"),
                context="verifying the AWS caller identity",
            )

        principal = response.get("Arn")
        return AuthenticatedCloudIdentity(
            provider=CloudProvider.AWS,
            account_id=account_id.strip(),
            # AWS has no second identity scope; Azure's Entra tenant has
            # no AWS analogue, so this stays None rather than being
            # filled with something that merely looks similar.
            directory_id=None,
            # An ARN identifies the principal and is not a credential —
            # it appears in every policy document we already collect.
            principal=principal if isinstance(principal, str) and principal.strip() else None,
        )


__all__ = ["AwsIdentityProvider"]
