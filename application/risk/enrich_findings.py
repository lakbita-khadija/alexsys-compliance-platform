"""``EnrichFindingsWithRisk`` — the link between findings and attack paths.

The missing pipeline stage. `ScanCloudAccount` produced findings and
(now) attack paths, and nothing joined them, so a finding on a resource
sitting at the end of a critical attack path looked exactly like the same
finding on an isolated resource.

## What it does and does not do

It **reuses** `EnrichRisk` rather than reimplementing the CRSF-1.1
formula — that component was correct all along, it simply had no caller
(current-state audit). `derive_factors` supplies the five factors;
`EnrichRisk` applies the blueprint's weights; this class joins findings
to paths and writes the result back.

It writes to **two fields that already exist**: `Finding.risk` and
`Finding.related_attack_path_ids`. Both were declared in Phase 1, both
already have columns and mappers, and neither was ever populated. So
attack-path risk reaches the database with **no schema change** — the
storage was built for this and left empty.

Paths are referenced by id, never embedded. A `Finding` carrying a full
copy of every `AttackPath` would duplicate the nodes and edges of the
graph into every row that touches them.

## Backward compatibility

A finding on no attack path keeps `related_attack_path_ids=()` and still
receives a risk score — from severity, environment and confidence, with a
zero attack-path contribution. That is the honest reading of CRSF-1.1:
attack-path involvement is one of five factors, not a precondition for
having risk at all.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from application.risk.enrich_risk import EnrichRisk
from application.risk.factors import FACTOR_MODEL_VERSION, derive_factors
from domain.attack_paths.models import AttackPath
from domain.findings.models import Finding
from domain.shared.identifiers import ResourceId


class EnrichFindingsWithRisk:
    """Joins findings to attack paths and scores the result."""

    def __init__(self, enrich_risk: EnrichRisk | None = None) -> None:
        self._enrich_risk = enrich_risk or EnrichRisk()

    def enrich(
        self,
        *,
        findings: Sequence[Finding],
        attack_paths: Sequence[AttackPath],
    ) -> tuple[Finding, ...]:
        """Return the findings with `risk` and attack-path references set.

        Order is preserved: callers downstream (persistence, scoring,
        the API) already depend on finding order being the evaluation
        order, and reordering here would be an invisible behaviour change.
        """

        paths_by_resource: dict[ResourceId, list[AttackPath]] = {}
        for path in attack_paths:
            # A path implicates every resource ALONG it, not just its
            # target. An instance mid-chain is genuinely part of the
            # attack, and a responder who only sees the endpoint cannot
            # break the chain anywhere else.
            for node in path.nodes:
                if node.is_external:
                    # The internet is on the path by construction; it is
                    # not a resource anyone can remediate, and attaching
                    # findings to it would be meaningless.
                    continue
                paths_by_resource.setdefault(node.resource_id, []).append(path)

        enriched: list[Finding] = []
        for finding in findings:
            paths = paths_by_resource.get(finding.resource_id, [])
            factors, environment_defaulted = derive_factors(finding, paths)
            score = self._enrich_risk.enrich(factors)

            path_ids = tuple(sorted({p.id for p in paths}, key=str))
            enriched.append(
                replace(
                    finding,
                    risk=score.value,
                    related_attack_path_ids=path_ids,
                    evidence=self._annotate(
                        finding,
                        risk_model=score.model_version,
                        factor_model=FACTOR_MODEL_VERSION,
                        path_count=len(paths),
                        environment_defaulted=environment_defaulted,
                    ),
                )
            )
        return tuple(enriched)

    @staticmethod
    def _annotate(
        finding: Finding,
        *,
        risk_model: str,
        factor_model: str,
        path_count: int,
        environment_defaulted: bool,
    ):
        """Record how the risk was reached, inside the existing evidence.

        Not a new field: `Evidence.data` is already the place a finding
        keeps the facts behind it, and adding a parallel structure would
        split one answer across two locations.

        `environment_defaulted` is surfaced deliberately. A score that
        silently assumed an unknown environment looks identical to one
        that measured it, and the difference changes how much weight a
        reader should give the number.
        """

        from domain.findings.models import Evidence

        return Evidence(
            data={
                **dict(finding.evidence.data),
                "risk_model_version": risk_model,
                "risk_factor_model_version": factor_model,
                "attack_path_count": path_count,
                "risk_environment_defaulted": environment_defaulted,
            }
        )


__all__ = ["EnrichFindingsWithRisk"]
