"""Deterministic translation from Domain entities to AI Service contract
DTOs (the Anti-Corruption Layer described, but not yet built, in
blueprint §26.5/§26.12).

Both functions are pure and strict: given the same domain object they
always produce the same contract object (or the same rejection), and
they never guess. In particular:

* ``finding_to_contract`` rejects an ``INDETERMINATE`` finding outright —
  the AI Service must never see it (its ``status`` contract has no third
  value to represent it).
* ``finding_to_contract`` rejects a ``Finding.framework``/``Finding.domain``
  that is not already exactly one of the AI Service's closed vocabulary
  values. The Domain intentionally keeps these as free strings (§9); this
  function does not invent a mapping from arbitrary internal strings to
  the external enums — that mapping does not exist anywhere in the
  blueprint or the handoff beyond the enums' own literal values, so
  guessing one would be inventing business logic. A ``Finding`` destined
  to cross this boundary must already be tagged with a recognized value.
* ``resource_to_contract`` requires the caller to supply ``service``
  explicitly. The Domain's ``resource_type`` is an opaque,
  provider-specific string (e.g. ``"security_group"``) by design (§8);
  splitting it into the handoff's separate ``service``/``type`` fields
  (e.g. ``"s3"``/``"bucket"``) is not a mechanical operation — no
  parsing convention is specified beyond a single example, and any
  string-splitting heuristic would silently produce wrong values for
  resource types that don't happen to fit the pattern (e.g.
  ``"security_group"`` does not decompose into a correct AWS service
  name). See docs/architecture/phase-1-domain.md, Known Limitations.
"""

from __future__ import annotations

from domain.findings.models import Finding, FindingStatus
from domain.resources.models import NormalizedResource

from contracts.ai_service.enums import ExternalFindingStatus, Framework, RiskDomain
from contracts.ai_service.models import FindingContract, NormalizedResourceContract
from contracts.errors import ContractTranslationError

_STATUS_MAP = {
    FindingStatus.PASS: ExternalFindingStatus.PASS,
    FindingStatus.FAIL: ExternalFindingStatus.FAIL,
}


def finding_to_contract(finding: Finding) -> FindingContract:
    """Translate a domain ``Finding`` into the AI Service's
    ``FindingContract``. Raises ``ContractTranslationError`` if the
    finding cannot be represented in the external contract as-is.
    """

    if finding.status not in _STATUS_MAP:
        raise ContractTranslationError(
            f"a {finding.status.value} finding cannot cross the AI Service boundary "
            "(the external contract has no INDETERMINATE status)"
        )

    try:
        framework = Framework(finding.framework)
    except ValueError:
        raise ContractTranslationError(
            f"finding.framework {finding.framework!r} is not a recognized AI Service framework"
        ) from None

    try:
        risk_domain = RiskDomain(finding.domain)
    except ValueError:
        raise ContractTranslationError(
            f"finding.domain {finding.domain!r} is not a recognized AI Service risk domain"
        ) from None

    return FindingContract(
        id=str(finding.id),
        tenant_id=str(finding.tenant_id),
        resource_id=str(finding.resource_id),
        rule_id=str(finding.rule_id),
        framework=framework,
        control_id=finding.control_id,
        domain=risk_domain,
        status=_STATUS_MAP[finding.status],
        severity=finding.severity,
        evidence=finding.evidence.data,
        detected_at=finding.detected_at,
    )


def resource_to_contract(resource: NormalizedResource, *, service: str) -> NormalizedResourceContract:
    """Translate a domain ``NormalizedResource`` into the AI Service's
    ``NormalizedResourceContract``. ``service`` cannot be derived from
    ``resource.resource_type`` (see module docstring) and must be
    supplied by the caller.
    """

    if not isinstance(service, str) or not service.strip():
        raise ContractTranslationError("service must be a non-blank string")

    return NormalizedResourceContract(
        id=str(resource.resource_id),
        tenant_id=str(resource.tenant_id),
        cloud=resource.cloud_provider,
        service=service,
        region=resource.region,
        type=resource.resource_type,
        config=resource.attributes,
        collected_at=resource.collected_at,
    )
