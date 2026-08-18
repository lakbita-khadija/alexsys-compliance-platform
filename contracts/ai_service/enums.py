"""Closed vocabularies specific to the Core <-> AI Service contract.

These are NOT Domain enums. The Domain (blueprint §9, ADR-003/§8) keeps
``Rule.framework``/``Rule.domain``/``Finding.framework``/``Finding.domain``
as free strings by design, to avoid a premature closed category before
it is proven necessary. The AI Service integration handoff, however, is
an external contract that *does* mandate a fixed vocabulary for its own
``framework``/``domain`` fields — so that vocabulary is modeled here, at
the boundary, and enforced only when a ``Finding`` is translated across
it (``contracts.ai_service.translation``), never inside the Domain
itself.

``Severity`` and ``CloudProvider`` are NOT duplicated here: the handoff's
values for both are identical to the Domain's (``domain.shared.enums``),
so the Domain enums are reused directly rather than re-declared.
"""

from __future__ import annotations

from enum import Enum


class Framework(str, Enum):
    """Compliance frameworks recognized by the AI Service contract."""

    ISO_27001 = "iso_27001"
    LOI_05_20 = "loi_05_20"
    DNSSI = "dnssi"
    NIST_CSF = "nist_csf"
    SOC_2 = "soc_2"


class RiskDomain(str, Enum):
    """Risk domains recognized by the AI Service contract."""

    IAM = "iam"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    STORAGE = "storage"


class ExternalFindingStatus(str, Enum):
    """The AI Service's two-valued finding status.

    Named ``External...`` (rather than reusing the name
    ``ComplianceStatus``) to avoid colliding with
    ``domain.compliance.models.ComplianceStatus``, a distinct concept
    (a per-control aggregate verdict, not a single finding's outcome).

    Deliberately has no ``INDETERMINATE`` value — the Domain's
    three-valued ``FindingStatus`` is never fully representable here by
    design; translating an ``INDETERMINATE`` finding must fail loudly
    (``ContractTranslationError``), not silently coerce to one of these
    two values.
    """

    PASS = "pass"
    FAIL = "fail"
