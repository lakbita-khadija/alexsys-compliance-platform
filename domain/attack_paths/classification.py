"""Security semantics for attack path analysis.

Turns two raw graph facts — *what kind of thing is this node* and *can an
attacker actually travel along this edge* — into the vocabulary the
analyzer reasons in. Pure domain logic: no I/O, no clock, no provider
branching.

**Why this is not `if aws: ... elif azure: ...`** (§18). An S3 bucket and
an Azure storage account are the same thing to an attacker: data at rest
that may be readable from outside. The analyzer reasons about
``ResourceRole.STORAGE``, and only this module knows which concrete
resource types map to it. Adding a provider means adding table rows, not
branches.

**Why the tables are closed and small.** Every entry names a resource
type some collector actually produces. A row for a type nobody collects
would be a rule that can never fire, dressed up as coverage.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from domain.graph.models import GraphEdge, GraphNode
from domain.shared.enums import RelationshipType
from domain.shared.unknown import is_unknown


class ResourceRole(Enum):
    """What a resource *is*, in attack terms.

    Normalized across providers so the analyzer never asks "is this AWS".
    """

    #: Outside the scan boundary — the internet, a foreign account, a
    #: service principal. Where an external attacker starts.
    EXTERNAL = "external"
    #: An identity that can be assumed and carries permissions.
    IDENTITY = "identity"
    #: Compute an attacker can land on.
    WORKLOAD = "workload"
    #: Data at rest. The usual objective.
    STORAGE = "storage"
    #: Key material. Compromise here is worse than data loss.
    SECRETS = "secrets"
    #: Firewalls and security groups — they gate reachability rather
    #: than being a target themselves.
    NETWORK_CONTROL = "network_control"
    #: Audit trails. A target because tampering hides everything else.
    AUDIT_LOG = "audit_log"
    #: Collected, classified by nobody. Never a target, never an entry.
    OTHER = "other"


#: resource_type -> role. Only types a collector actually emits (audit
#: §2). `iam_account_summary` is deliberately OTHER: it is an account
#: setting report, not a resource an attacker traverses.
_ROLE_BY_RESOURCE_TYPE: Mapping[str, ResourceRole] = {
    # --- AWS
    "ec2_instance": ResourceRole.WORKLOAD,
    "s3_bucket": ResourceRole.STORAGE,
    # A managed database is data-bearing in exactly the sense STORAGE
    # means (STEP 8B). Left unclassified it would be OTHER — never
    # worth reaching — which would mean collecting the production
    # database and then treating it as irrelevant to risk.
    #
    # This adds no new scenario. It lets the existing ones see a type
    # they should always have seen, and it produces no spurious path:
    # the public-store scenarios require `public`-family attributes
    # that RDS deliberately does not set (see normalizers/rds.py).
    "rds_db_instance": ResourceRole.STORAGE,
    "iam_role": ResourceRole.IDENTITY,
    "iam_user": ResourceRole.IDENTITY,
    "kms_key": ResourceRole.SECRETS,
    "security_group": ResourceRole.NETWORK_CONTROL,
    "cloudtrail": ResourceRole.AUDIT_LOG,
    "iam_account_summary": ResourceRole.OTHER,
    # --- Azure
    "azure_virtual_machine": ResourceRole.WORKLOAD,
    "azure_storage_account": ResourceRole.STORAGE,
    "azure_key_vault": ResourceRole.SECRETS,
    "azure_network_security_group": ResourceRole.NETWORK_CONTROL,
    "azure_activity_log_setting": ResourceRole.AUDIT_LOG,
    # An Entra principal is an identity in exactly the sense IDENTITY
    # means, matching `iam_role`/`iam_user` (STEP 8C). Left
    # unclassified it would be OTHER — never worth reaching — so the
    # analyzer would collect every privileged principal and then treat
    # it as irrelevant to risk.
    #
    # This adds no scenario and produces no path: every RBAC edge is
    # informational (ATTACHED_TO / ALLOWS), so nothing traverses TO a
    # principal. It affects how a principal is described if some future
    # traversable edge ever reaches one.
    "azure_principal": ResourceRole.IDENTITY,
    # The assignment and the definition are authorization records, not
    # things an attacker reaches. OTHER is correct and is stated
    # explicitly so neither silently inherits a role later.
    "azure_role_assignment": ResourceRole.OTHER,
    "azure_role_definition": ResourceRole.OTHER,
    # A subscription is a scope container, not a target.
    "azure_subscription": ResourceRole.OTHER,
    # --- External (materialized by BuildResourceGraph, not collected)
    "internet": ResourceRole.EXTERNAL,
    "aws_account": ResourceRole.EXTERNAL,
    "aws_service": ResourceRole.EXTERNAL,
    "azure_tenant": ResourceRole.EXTERNAL,
    "external_resource": ResourceRole.EXTERNAL,
}

#: Roles worth reaching. A path that ends at a NETWORK_CONTROL has
#: reached a firewall, which is not a prize.
_SENSITIVE_ROLES = frozenset(
    {ResourceRole.STORAGE, ResourceRole.SECRETS, ResourceRole.IDENTITY, ResourceRole.AUDIT_LOG}
)

#: Roles that actually hold data. A subset of the sensitive roles, and
#: the distinction is not pedantic: an IAM role is a valuable target but
#: it does not *store* anything. Without this split, a publicly assumable
#: role was reported as "holds sensitive data and is readable from the
#: internet" — a true risk described by a false sentence, ranked above
#: the correctly-worded path for the same resource. Found by running the
#: analyzer, not by review.
_DATA_BEARING_ROLES = frozenset(
    {ResourceRole.STORAGE, ResourceRole.SECRETS, ResourceRole.AUDIT_LOG}
)

#: Relationships an attacker can actually travel along.
#:
#: ATTACHED_TO and ALLOWS are NOT here, and that is the single most
#: important decision in this module. "This instance is attached to a
#: security group" describes configuration, not movement — an attacker
#: does not travel *into* a firewall. Treating every edge as traversable
#: is exactly how a graph turns into a false-positive generator (§6).
_TRAVERSABLE_RELATIONSHIPS = frozenset(
    {
        RelationshipType.ASSUMES,
        RelationshipType.ACCESSES,
        RelationshipType.PUBLICLY_EXPOSED,
        RelationshipType.CONNECTS_TO,
    }
)

#: Relationships that describe topology or policy rather than movement.
#: Kept as an explicit set rather than "everything else" so that adding a
#: relationship type forces a decision instead of silently defaulting to
#: traversable.
_INFORMATIONAL_RELATIONSHIPS = frozenset(
    {
        RelationshipType.ATTACHED_TO,
        RelationshipType.ALLOWS,
        RelationshipType.CONTAINS,
        RelationshipType.PROTECTS,
    }
)

#: Attributes that, when TRUE, mean "reachable from the public internet".
#: Read from the resource that owns them — never inferred from a
#: neighbour.
_PUBLIC_EXPOSURE_ATTRIBUTES = (
    "public",
    "bucket_policy_allows_public_access",
    "is_publicly_assumable",
    "allows_public_network_access",
    "public_network_access_enabled",
)

#: Attributes that mean "this identity carries dangerous privilege".
_PRIVILEGE_ATTRIBUTES = (
    "has_administrator_access",
    "has_privilege_escalation_path",
    "has_pass_role_escalation",
    "has_wildcard_action",
)


def role_of(node: GraphNode) -> ResourceRole:
    """Classify a node. Unknown types are ``OTHER``, never guessed.

    External nodes are ``EXTERNAL`` regardless of their type string,
    because ``kind`` is the authoritative statement that the resource was
    never enumerated.
    """

    if node.is_external:
        return ResourceRole.EXTERNAL
    return _ROLE_BY_RESOURCE_TYPE.get(node.resource_type, ResourceRole.OTHER)


def is_sensitive(node: GraphNode) -> bool:
    """Whether reaching this node is worth reporting."""

    return role_of(node) in _SENSITIVE_ROLES


def is_data_bearing(node: GraphNode) -> bool:
    """Whether this node stores data an attacker would exfiltrate.

    Narrower than :func:`is_sensitive` on purpose — see
    ``_DATA_BEARING_ROLES``.
    """

    return role_of(node) in _DATA_BEARING_ROLES


def is_traversable(edge: GraphEdge) -> bool:
    """Whether an attacker can move along this edge.

    ``blocked`` edges are excluded here rather than at the caller, so
    every consumer inherits the same answer. An edge that exists
    structurally but is prevented in practice is not a step in an attack.
    """

    if edge.blocked:
        return False
    return edge.relationship_type in _TRAVERSABLE_RELATIONSHIPS


def is_informational(edge: GraphEdge) -> bool:
    """Whether this edge describes configuration rather than movement."""

    return edge.relationship_type in _INFORMATIONAL_RELATIONSHIPS


def _definitely_true(value: Any) -> bool:
    """``True`` only for a genuine boolean ``True``.

    ``UNKNOWN`` is the reason this helper exists. ``bool(UNKNOWN)`` raises
    by design, and a bare truthiness check on a collected attribute is
    how "we could not read this" becomes "this is definitely public" —
    the exact false accusation ``domain/shared/unknown.py`` was written
    to prevent. Anything that is not literally ``True`` is not evidence.
    """

    if is_unknown(value):
        return False
    return value is True


def _has_unknown(attributes: Mapping[str, Any], names: tuple[str, ...]) -> bool:
    return any(is_unknown(attributes.get(name)) for name in names)


def public_exposure_evidence(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    """Which attributes assert that this resource is internet-reachable.

    Returns the attribute names, not a boolean, because a finding must be
    able to say *why* — "public: true" and "bucket policy allows a
    wildcard principal" are different facts a responder acts on
    differently.
    """

    return tuple(
        name for name in _PUBLIC_EXPOSURE_ATTRIBUTES if _definitely_true(attributes.get(name))
    )


def exposure_is_undetermined(attributes: Mapping[str, Any]) -> bool:
    """Whether exposure could not be read rather than being absent.

    Drives the incompleteness penalty: "we could not determine whether
    this bucket is public" must not score the same as "this bucket is
    confirmed private".
    """

    return _has_unknown(attributes, _PUBLIC_EXPOSURE_ATTRIBUTES)


def privilege_evidence(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    """Which attributes assert that this identity is dangerous."""

    return tuple(name for name in _PRIVILEGE_ATTRIBUTES if _definitely_true(attributes.get(name)))


def privilege_is_undetermined(attributes: Mapping[str, Any]) -> bool:
    """Whether privilege analysis was denied.

    ``IamRoleCollector`` sets every privilege attribute to ``UNKNOWN``
    when policy enumeration is denied. A path built on that is a guess,
    and the score must say so.
    """

    return _has_unknown(attributes, _PRIVILEGE_ATTRIBUTES)


def unrestricted_ingress_evidence(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    """Whether a network control lets the whole internet in."""

    evidence = []
    if _definitely_true(attributes.get("has_unrestricted_ingress")):
        evidence.append("has_unrestricted_ingress")
    if _definitely_true(attributes.get("allows_unrestricted_ingress")):
        evidence.append("allows_unrestricted_ingress")
    ports = attributes.get("unrestricted_ingress_ports")
    if not is_unknown(ports) and isinstance(ports, (list, tuple)) and ports:
        evidence.append("unrestricted_ingress_ports")
    return tuple(evidence)


__all__ = [
    "ResourceRole",
    "exposure_is_undetermined",
    "is_data_bearing",
    "is_informational",
    "is_sensitive",
    "is_traversable",
    "privilege_evidence",
    "privilege_is_undetermined",
    "public_exposure_evidence",
    "role_of",
    "unrestricted_ingress_evidence",
]
