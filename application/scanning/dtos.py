"""DTOs for ``ScanCloudAccount`` (blueprint §4).

``ScanConfiguration`` — blueprint names this as one of ``ScanCloudAccount``'s
four input fields but gives it no further specification anywhere else
in the document. The only shape that can be added without inventing a
business rule is a filter over an already-fully-specified Domain
concept: which rules to run. Everything else about "configuring a scan"
is genuinely unspecified and intentionally absent (see
docs/architecture/phase-2-application.md, Known Limitations) — this is
a minimal, documented placeholder, not a claim that scan configuration
is fully modeled.

``ScanResult`` — named as the use case's output (blueprint §4) but its
fields are nowhere enumerated. The fields below are exactly what the
declared pipeline (§4's "Séquence interne") naturally produces at each
stage; nothing here encodes a business rule, only an aggregation of
already-defined Domain outputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from domain.attack_paths.models import AttackPath
from domain.drift.models import DriftEvent
from domain.findings.models import Finding
from domain.graph.models import ResourceGraph
from domain.resources.models import NormalizedResource
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import RuleId, TenantId


@dataclass(frozen=True, slots=True)
class ScanConfiguration:
    """Minimal, documented placeholder — see module docstring."""

    rule_ids: tuple[RuleId, ...] | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The outcome of one ``ScanCloudAccount`` run."""

    scan_id: str
    tenant_id: TenantId
    provider: CloudProvider
    scanned_at: datetime
    resources: tuple[NormalizedResource, ...]
    graph: ResourceGraph
    findings: tuple[Finding, ...]
    attack_paths: tuple[AttackPath, ...]
    drift_events: tuple[DriftEvent, ...]
