"""How to obtain an AWS session — never the credentials themselves.

``AwsCredentialConfig`` intentionally has no ``aws_access_key_id``/
``aws_secret_access_key``/``aws_session_token`` fields. Per the Phase 3
brief's explicit preference order (SDK default credential chain > env
vars > profile > IAM role > explicit keys only if strictly necessary),
this project supports only the first four — a named profile (which
itself resolves via boto3's own default chain: env vars, shared
credentials file, or an attached IAM role) and, optionally, assuming a
role via STS. Raw long-lived access keys are never modeled, so there is
no field here that could ever hold one, and nothing in this codebase
can accidentally log or serialize one that was never stored.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AwsCredentialConfig:
    """Configuration for how to obtain an AWS session — a strategy
    pointer, never a secret.
    """

    region: str
    profile: str | None = None
    role_arn: str | None = None
    #: The ``sts:ExternalId`` to present when assuming ``role_arn``
    #: (STEP 6.5).
    #:
    #: The standard defence against the confused-deputy problem for a
    #: SaaS scanner: a customer's cross-account role carries an
    #: ``sts:ExternalId`` condition, so knowing the role ARN — which is
    #: not secret and appears in their own console — is not enough to
    #: assume it. Without this field a customer could not configure that
    #: protection even if they wanted to.
    #:
    #: Optional, because the existing single-account paths (default
    #: chain, named profile, plain AssumeRole) are unaffected and must
    #: stay working.
    #:
    #: ``repr=False`` on purpose. This is not a credential — it is a
    #: shared identifier, and AWS documents it as not secret — but it is
    #: an access-control input, and a config object that prints it ends
    #: up in a traceback, a log line, and eventually a ticket.
    external_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.region, str) or not self.region.strip():
            raise ValueError("region must be a non-blank string")
        if self.profile is not None and not self.profile.strip():
            raise ValueError("profile must be None or a non-blank string")
        if self.role_arn is not None and not self.role_arn.strip():
            raise ValueError("role_arn must be None or a non-blank string")
        if self.external_id is not None:
            if not isinstance(self.external_id, str) or not self.external_id.strip():
                raise ValueError("external_id must be None or a non-blank string")
            # An external id with no role to assume is a configuration
            # mistake that silently does nothing: STS only consults it
            # during AssumeRole. Failing here turns "my external id is
            # being ignored" into an error at construction rather than a
            # security control the operator believes is active.
            if self.role_arn is None:
                raise ValueError(
                    "external_id is only meaningful with role_arn; "
                    "STS consults it during AssumeRole and nowhere else"
                )
