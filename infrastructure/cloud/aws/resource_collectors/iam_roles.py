"""IAM role collector (§4.1).

The first collector built on all three of this upgrade's foundations at
once, and it is the reference for the ones that follow:

* **resilience** — every SDK call goes through ``call_with_retry``, and
  per-role enrichment is isolated so one inaccessible role does not lose
  the other 9,999
* **UNKNOWN** — a denied ``list_attached_role_policies`` yields
  ``UNKNOWN``, never ``False``. "We could not read this role's policies"
  must never render as "this role has no dangerous policies"
* **semantic analysis** — trust and permission policies are parsed and
  evaluated (``policy_analysis``), not matched by name

## The permission model

`iam:ListRoles` alone gets role metadata and the trust policy — the
latter arrives inline in `list_roles`, so cross-account and public-trust
detection works with minimal permission.

Policy analysis additionally needs `iam:ListAttachedRolePolicies`,
`iam:ListRolePolicies`, `iam:GetRolePolicy` and `iam:GetPolicyVersion`.
When those are missing the role is still collected, with policy
attributes as UNKNOWN — a degraded but honest result, and the operator
sees exactly which permission to grant.

`iam:GetRole` is called for `RoleLastUsed`, which `list_roles` omits.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId
from domain.shared.unknown import UNKNOWN
from infrastructure.cloud.aws.errors import translate_client_error
from infrastructure.cloud.aws.policy_analysis import (
    extract_access_grants,
    analyze_policy_documents,
    analyze_trust_policy,
    to_attributes,
)
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector
from infrastructure.cloud.resilience import (
    CollectionStats,
    RetryPolicy,
    call_with_retry,
    collect_each,
    is_permission_denied,
    paginate,
)

#: Attributes set to UNKNOWN when policy enumeration is denied. Named
#: once so the degraded shape is identical everywhere and a rule can
#: rely on it.
_POLICY_ATTRIBUTES = (
    "has_administrator_access",
    "has_wildcard_action",
    "has_wildcard_resource",
    "has_privilege_escalation_path",
    "has_pass_role_escalation",
)


class IamRoleCollector(AwsResourceCollector):
    """Collects IAM roles with semantic trust and permission analysis."""

    resource_type = "IAM roles"

    def __init__(
        self,
        *,
        session,
        tenant_id,
        clock,
        account_id: str | None = None,
        retry_policy: RetryPolicy | None = None,
        stats: CollectionStats | None = None,
    ) -> None:
        super().__init__(
            session=session, tenant_id=tenant_id, clock=clock, account_id=account_id
        )
        self._retry_policy = retry_policy or RetryPolicy()
        self.stats = stats if stats is not None else CollectionStats()

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("iam")
        collected_at = self._clock()

        try:
            roles = self._list_roles(client)
        except Exception as exc:  # noqa: BLE001 - re-raised as a typed AWS error
            # Listing roles is the one call with no fallback: without it
            # there is nothing to collect, so this is fatal for this
            # sub-collector (and isolated by AwsCollector._safe()).
            raise translate_client_error(exc, context="listing IAM roles") from exc

        # Per-role enrichment is isolated: one role whose policies cannot
        # be read must not lose every other role in the account.
        resources = collect_each(
            roles,
            lambda role: self._normalize(client, role, collected_at),
            stats=self.stats,
            describe=lambda role: f"IAM role {role.get('RoleName', '<unnamed>')}",
        )
        return tuple(resources)

    def _list_roles(self, client) -> list[dict[str, Any]]:
        roles: list[dict[str, Any]] = []
        for page in paginate(
            client.get_paginator("list_roles").paginate(),
            policy=self._retry_policy,
            stats=self.stats,
            description="iam:ListRoles",
        ):
            roles.extend(page.get("Roles", []))
        return roles

    def _normalize(
        self, client, role: dict[str, Any], collected_at: datetime
    ) -> NormalizedResource:
        role_name = role["RoleName"]
        arn = role.get("Arn", "")

        # The trust policy arrives inline with list_roles, so this works
        # with only iam:ListRoles — the most valuable analysis is also
        # the cheapest to obtain.
        trust = analyze_trust_policy(
            role.get("AssumeRolePolicyDocument"), own_account_id=self._account_id
        )

        policy_documents, policies_readable, attached, inline = self._policy_documents(
            client, role_name
        )
        policy = analyze_policy_documents(policy_documents)

        attributes: dict[str, Any] = {
            "role_name": role_name,
            "arn": arn,
            "path": role.get("Path"),
            "description": role.get("Description"),
            "max_session_duration": role.get("MaxSessionDuration"),
            "create_date": _isoformat(role.get("CreateDate")),
            # A service-linked role is managed by AWS and cannot be
            # edited, so several controls do not meaningfully apply to
            # it. Surfaced so rules can exclude them rather than
            # generating findings nobody can act on.
            "is_service_role": str(role.get("Path", "")).startswith("/aws-service-role/"),
        }

        attributes.update(to_attributes(policy, trust))

        # Raw grants for identity -> resource edge derivation (STEP 2).
        # Stored as plain mappings, not domain objects: `attributes`
        # crosses into persistence and the AI contract, so it must stay
        # JSON-shaped. `domain/graph/identity_access.py` rehydrates them
        # and decides which become edges — this collector decides
        # nothing.
        attributes["access_grants"] = (
            extract_access_grants(policy_documents) if policies_readable else UNKNOWN
        )

        if policies_readable:
            attributes["attached_policy_count"] = len(attached)
            attributes["inline_policy_count"] = len(inline)
            attributes["attached_policy_names"] = attached
            attributes["inline_policy_names"] = inline
        else:
            # The critical distinction (§34). Denied enumeration is NOT
            # "no dangerous policies" — that would be a false negative
            # dressed as a clean result, which is worse than a false
            # positive because nobody investigates it.
            for name in _POLICY_ATTRIBUTES:
                attributes[name] = UNKNOWN
            attributes["attached_policy_count"] = UNKNOWN
            attributes["inline_policy_count"] = UNKNOWN
            attributes["policy_analysis_confidence"] = "unknown"

        last_used, last_used_known = self._last_used(client, role_name)
        attributes["last_used"] = last_used if last_used_known else UNKNOWN

        return NormalizedResource(
            resource_id=ResourceId(arn or f"iam-role:{role_name}"),
            resource_type="iam_role",
            cloud_provider=CloudProvider.AWS,
            tenant_id=self._tenant_id,
            region=None,  # IAM is global.
            attributes=attributes,
            tags={t["Key"]: t["Value"] for t in role.get("Tags", []) if "Key" in t},
            relationships=self._relationships(trust),
            collected_at=collected_at,
            account_id=self._account_id,
        )

    def _policy_documents(
        self, client, role_name: str
    ) -> tuple[list[Any], bool, list[str], list[str]]:
        """Fetch every policy document attached to or inline on a role.

        Returns ``(documents, readable, attached_names, inline_names)``.
        ``readable=False`` means enumeration was denied and the caller
        must record UNKNOWN rather than an empty result.
        """

        documents: list[Any] = []
        attached_names: list[str] = []
        inline_names: list[str] = []

        try:
            for page in paginate(
                client.get_paginator("list_attached_role_policies").paginate(
                    RoleName=role_name
                ),
                policy=self._retry_policy,
                stats=self.stats,
                description="iam:ListAttachedRolePolicies",
            ):
                for attached in page.get("AttachedPolicies", []):
                    attached_names.append(attached.get("PolicyName", ""))
                    document = self._managed_policy_document(client, attached.get("PolicyArn"))
                    if document is not None:
                        documents.append(document)

            for page in paginate(
                client.get_paginator("list_role_policies").paginate(RoleName=role_name),
                policy=self._retry_policy,
                stats=self.stats,
                description="iam:ListRolePolicies",
            ):
                for policy_name in page.get("PolicyNames", []):
                    inline_names.append(policy_name)
                    response = call_with_retry(
                        lambda: client.get_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        ),
                        policy=self._retry_policy,
                        stats=self.stats,
                        description="iam:GetRolePolicy",
                    )
                    documents.append(response.get("PolicyDocument"))

        except Exception as exc:  # noqa: BLE001 - degraded, not fatal
            if is_permission_denied(exc):
                # Honest degradation: the role is still collected, with
                # policy attributes UNKNOWN, and the operator learns
                # which permission the scanner is missing.
                return [], False, [], []
            raise

        return documents, True, attached_names, inline_names

    def _managed_policy_document(self, client, policy_arn: str | None) -> Any:
        """Resolve a managed policy ARN to its default version document.

        Two calls per policy, which is why the result matters: a
        customer-managed policy named ``DeveloperAccess`` granting
        ``*:*`` is invisible to name matching and is exactly what this
        upgrade exists to catch.
        """

        if not policy_arn:
            return None
        try:
            policy = call_with_retry(
                lambda: client.get_policy(PolicyArn=policy_arn),
                policy=self._retry_policy,
                stats=self.stats,
                description="iam:GetPolicy",
            )
            version_id = policy.get("Policy", {}).get("DefaultVersionId")
            if not version_id:
                return None
            version = call_with_retry(
                lambda: client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                ),
                policy=self._retry_policy,
                stats=self.stats,
                description="iam:GetPolicyVersion",
            )
            return version.get("PolicyVersion", {}).get("Document")
        except Exception as exc:  # noqa: BLE001
            if is_permission_denied(exc):
                # One unreadable policy must not discard the others.
                self.stats.permission_denied += 1
                return None
            raise

    def _last_used(self, client, role_name: str) -> tuple[str | None, bool]:
        """``RoleLastUsed``, which ``list_roles`` does not return.

        Returns ``(value, known)``. A denied ``GetRole`` yields
        ``known=False`` so the caller records UNKNOWN — reporting an
        unused role as "never used" on the strength of a permission error
        would recommend deleting a role that is in daily use.
        """

        try:
            response = call_with_retry(
                lambda: client.get_role(RoleName=role_name),
                policy=self._retry_policy,
                stats=self.stats,
                description="iam:GetRole",
            )
        except Exception as exc:  # noqa: BLE001
            if is_permission_denied(exc):
                return None, False
            raise

        last_used = response.get("Role", {}).get("RoleLastUsed", {})
        # An empty RoleLastUsed is a KNOWN fact: AWS returns it for a
        # role that has genuinely never been used. Distinct from a denied
        # call, which is why `known` is True here.
        return _isoformat(last_used.get("LastUsedDate")), True

    @staticmethod
    def _relationships(trust) -> tuple[ResourceRelationship, ...]:
        """Edges derived from the trust policy.

        `ASSUMES` from each trusted principal is what makes cross-account
        reachability queryable in the graph, and `PUBLICLY_EXPOSED` marks
        a role anyone can assume — both previously unemitted relationship
        types (audit G4).
        """

        relationships: list[ResourceRelationship] = []

        for account_id in trust.external_account_ids:
            relationships.append(
                ResourceRelationship(
                    target_resource_id=ResourceId(f"aws-account:{account_id}"),
                    relationship_type=RelationshipType.ASSUMES,
                )
            )
        for service in trust.service_principals:
            relationships.append(
                ResourceRelationship(
                    target_resource_id=ResourceId(f"aws-service:{service}"),
                    relationship_type=RelationshipType.ASSUMES,
                )
            )
        if trust.is_publicly_assumable:
            relationships.append(
                ResourceRelationship(
                    target_resource_id=ResourceId("internet"),
                    relationship_type=RelationshipType.PUBLICLY_EXPOSED,
                )
            )
        return tuple(relationships)


def _isoformat(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None
