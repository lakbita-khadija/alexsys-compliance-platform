"""The pre-collection authentication gate (STEP 6.5).

Runs **before** a single resource is read. That ordering is the whole
control: once collection has happened, the resources exist in memory
tagged with the requesting tenant, and every later check is checking the
wrong thing.

What this is not
----------------
It is not a tenant-isolation check in the `TenantIsolationViolation`
sense — nothing has crossed a tenant boundary yet. It is not a resource
uncertainty either. The distinction the audit insisted on:

    AccessDenied reading a security group  →  UNKNOWN, scan continues
    Authenticated as the wrong account     →  scan rejected outright

The first is a gap in what we can see. The second means we are looking
at the wrong estate, and no amount of downstream care can repair a scan
that collected someone else's infrastructure under this tenant's name.

Audit emission
--------------
`AUTHENTICATION_FAILED` was declared in `AuditAction` from Phase 5 and
never emitted by anything (`core-auth-readiness.md` §8). This is one of
its call sites. The metadata carries account identifiers and the failure
reason — never a credential, and `AuditEvent` rejects credential-shaped
keys outright rather than redacting them, so a mistake here fails loudly
instead of leaking quietly.
"""

from __future__ import annotations

from application.ports.audit import AuditRecorder
from application.ports.cloud_identity import CloudAccountDirectory, CloudIdentityProvider
from domain.audit.models import AuditAction
from domain.shared.enums import CloudProvider
from domain.shared.errors import CloudIdentityMismatch
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import (
    AuthenticatedCloudIdentity,
    CloudAccountBinding,
    verify_cloud_identity,
)


class CloudAuthenticationFailure(CloudIdentityMismatch):
    """Identity could not be established at all.

    Distinct from a mismatch: a mismatch means the provider told us who
    we are and it was the wrong account; this means the provider would
    not tell us — missing credentials, an invalid key, an expired token,
    STS refusing the call, or a response we cannot parse.

    Both abort the scan, and the audit trail records them differently
    because an operator triages them differently: a mismatch is a
    configuration error, an authentication failure is a credential
    problem.
    """


class VerifyCloudIdentity:
    """Gate a scan on the authenticated cloud account matching the binding."""

    def __init__(
        self,
        *,
        identity_provider: CloudIdentityProvider,
        directory: CloudAccountDirectory,
        audit: AuditRecorder | None = None,
    ) -> None:
        self._identity_provider = identity_provider
        self._directory = directory
        self._audit = audit

    def execute(
        self,
        *,
        tenant_id: TenantId,
        provider: CloudProvider,
        actor_subject: str = "scanner",
        correlation_id: str | None = None,
    ) -> CloudAccountBinding:
        """Return the authorizing binding, or raise and record the failure."""

        identity = self._resolve_identity(
            tenant_id=tenant_id,
            provider=provider,
            actor_subject=actor_subject,
            correlation_id=correlation_id,
        )

        bindings = self._directory.bindings_for(tenant_id=tenant_id, provider=provider)

        try:
            return verify_cloud_identity(
                tenant_id=tenant_id, actual=identity, bindings=bindings
            )
        except CloudIdentityMismatch as exc:
            self._record_failure(
                tenant_id=tenant_id,
                provider=provider,
                actor_subject=actor_subject,
                correlation_id=correlation_id,
                reason="account_not_bound_to_tenant",
                detail=str(exc),
                identity=identity,
            )
            raise

    def _resolve_identity(
        self,
        *,
        tenant_id: TenantId,
        provider: CloudProvider,
        actor_subject: str,
        correlation_id: str | None,
    ) -> AuthenticatedCloudIdentity:
        try:
            return self._identity_provider.authenticated_identity()
        except Exception as exc:
            # Broad on purpose. Every way a provider can refuse to
            # identify us — a botocore ClientError, an Azure
            # ClientAuthenticationError, a malformed response, a socket
            # timeout — reaches the same conclusion: we do not know
            # which account this is, so we must not collect from it.
            # Narrowing this would let an unanticipated SDK exception
            # escape the gate and abort the scan through some other path
            # that records no audit event.
            self._record_failure(
                tenant_id=tenant_id,
                provider=provider,
                actor_subject=actor_subject,
                correlation_id=correlation_id,
                reason="identity_unavailable",
                # The exception TYPE, not its message: SDK messages can
                # embed request URLs, and an Azure SAS-style URL carries
                # its credential in the query string.
                detail=type(exc).__name__,
                identity=None,
            )
            raise CloudAuthenticationFailure(
                f"could not establish the authenticated {provider.value} identity "
                f"({type(exc).__name__}); refusing to scan an unidentified account"
            ) from exc

    def _record_failure(
        self,
        *,
        tenant_id: TenantId,
        provider: CloudProvider,
        actor_subject: str,
        correlation_id: str | None,
        reason: str,
        detail: str,
        identity: AuthenticatedCloudIdentity | None,
    ) -> None:
        if self._audit is None:
            return

        metadata: dict[str, object] = {
            "provider": provider.value,
            "reason": reason,
            "detail": detail,
        }
        if identity is not None:
            # Account and subscription identifiers are not secrets: an
            # AWS account id appears in every ARN and a subscription id
            # in every Azure resource id. The principal is an ARN or an
            # object id — an identifier, never a credential.
            metadata["authenticated_account_id"] = identity.account_id
            if identity.directory_id is not None:
                metadata["authenticated_directory_id"] = identity.directory_id
            if identity.principal is not None:
                metadata["authenticated_principal"] = identity.principal

        self._audit.record(
            tenant_id=tenant_id,
            actor_subject=actor_subject,
            action=AuditAction.AUTHENTICATION_FAILED,
            resource=identity.account_id if identity is not None else None,
            resource_type="cloud_account",
            correlation_id=correlation_id,
            metadata=metadata,
            actor_kind="system",
        )


__all__ = ["CloudAuthenticationFailure", "VerifyCloudIdentity"]
