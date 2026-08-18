"""Explicit domain <-> ORM mappers (Phase 4, Part 12).

Every translation between a domain object and a persistence row happens
here, in one direction at a time, by hand. No SQLAlchemy
``registry.map_imperatively``, no dataclass-to-ORM magic.

That is deliberate. The domain models are frozen, slotted dataclasses
with validating constructors; automatic mapping would either bypass
those validators (silently admitting invalid data on read) or fight
them. Writing the translation out makes every field's round trip
reviewable, and means a schema change that drops a field breaks a test
here rather than losing data quietly.

Direction matters:

* ``to_row``   — domain -> plain dict for bulk insert. Returns dicts,
  not ORM instances, because the repositories use SQLAlchemy Core bulk
  operations (Part 15) where ORM instances would be pure overhead.
* ``to_domain`` — ORM row -> reconstructed domain object, passing
  through the real constructor so every invariant is re-checked on the
  way out. A corrupted row fails loudly instead of propagating.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from domain.attack_paths.models import AttackPath
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.scans.lifecycle import LifecycleState, LogicalFinding
from domain.scans.models import Scan, ScanCounts, ScanError, ScanStatus, ScanTarget
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import AttackPathId, FindingId, ResourceId, RuleId, TenantId
from infrastructure.persistence.postgres.mappers.redaction import redact


def _utcnow() -> datetime:
    """The one place a clock is read in the persistence layer.

    Used only for bookkeeping columns (``created_at``/``updated_at``)
    that record when a ROW was written — never for any value that feeds
    a domain object or a finding's identity. Domain determinism is
    unaffected: every domain-meaningful timestamp is passed in.
    """

    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------


def scan_to_row(scan: Scan) -> dict[str, Any]:
    return {
        "scan_key": scan.scan_key,
        "tenant_id": str(scan.tenant_id),
        "provider": scan.target.provider.value,
        "account_id": scan.target.account_id,
        "directory_id": scan.target.directory_id,
        "regions": list(scan.target.regions),
        "status": scan.status.value,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_seconds": scan.duration_seconds,
        "resource_count": scan.counts.resource_count,
        "finding_count": scan.counts.finding_count,
        "critical_count": scan.counts.critical_count,
        "high_count": scan.counts.high_count,
        "medium_count": scan.counts.medium_count,
        "low_count": scan.counts.low_count,
        "pass_count": scan.counts.pass_count,
        "fail_count": scan.counts.fail_count,
        "indeterminate_count": scan.counts.indeterminate_count,
        "error_count": scan.counts.error_count,
        "scanner_version": scan.scanner_version,
        "ruleset_version": scan.ruleset_version,
        "correlation_id": scan.correlation_id,
        "legacy_scan_id": scan.legacy_scan_id,
        "created_at": _utcnow(),
    }


def scan_to_domain(row: Any, errors: tuple[ScanError, ...] = ()) -> Scan:
    return Scan(
        scan_key=row.scan_key,
        tenant_id=TenantId(row.tenant_id),
        target=ScanTarget(
            provider=CloudProvider(row.provider),
            account_id=row.account_id,
            directory_id=row.directory_id,
            regions=tuple(row.regions or ()),
        ),
        status=ScanStatus(row.status),
        started_at=row.started_at,
        completed_at=row.completed_at,
        counts=ScanCounts(
            resource_count=row.resource_count,
            finding_count=row.finding_count,
            critical_count=row.critical_count,
            high_count=row.high_count,
            medium_count=row.medium_count,
            low_count=row.low_count,
            pass_count=row.pass_count,
            fail_count=row.fail_count,
            indeterminate_count=row.indeterminate_count,
            error_count=row.error_count,
        ),
        errors=errors,
        scanner_version=row.scanner_version,
        ruleset_version=row.ruleset_version,
        correlation_id=row.correlation_id,
        legacy_scan_id=row.legacy_scan_id,
    )


def scan_error_to_row(error: ScanError, *, tenant_id: TenantId, scan_key: str) -> dict[str, Any]:
    return {
        "scan_key": scan_key,
        "tenant_id": str(tenant_id),
        "provider": error.provider.value,
        "service": error.service,
        "operation": error.operation,
        "error_code": error.error_code,
        # Sanitized on the way in — a scan error message must never
        # carry a credential (Part 20).
        "message": error.message,
        "retryable": error.retryable,
        "occurred_at": error.occurred_at,
    }


def scan_error_to_domain(row: Any) -> ScanError:
    return ScanError(
        provider=CloudProvider(row.provider),
        service=row.service,
        operation=row.operation,
        error_code=row.error_code,
        message=row.message,
        occurred_at=row.occurred_at,
        retryable=row.retryable,
    )


# ---------------------------------------------------------------------
# Resource snapshot
# ---------------------------------------------------------------------


def resource_to_row(
    resource: NormalizedResource, *, tenant_id: TenantId, scan_key: str
) -> dict[str, Any]:
    return {
        "scan_key": scan_key,
        "tenant_id": str(tenant_id),
        "resource_id": str(resource.resource_id),
        "resource_type": resource.resource_type,
        "provider": resource.cloud_provider.value,
        "account_id": resource.account_id,
        "region": resource.region,
        "collected_at": resource.collected_at,
        # `attributes` is where a future collector could most plausibly
        # leak a secret, so it is redacted rather than trusted.
        "attributes": redact(dict(resource.attributes)),
        "tags": dict(resource.tags),
        "relationships": [
            {
                "target_resource_id": str(rel.target_resource_id),
                "relationship_type": rel.relationship_type.value,
            }
            for rel in resource.relationships
        ],
    }


def resource_to_domain(row: Any) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(row.resource_id),
        resource_type=row.resource_type,
        cloud_provider=CloudProvider(row.provider),
        tenant_id=TenantId(row.tenant_id),
        region=row.region,
        attributes=dict(row.attributes or {}),
        tags=dict(row.tags or {}),
        relationships=tuple(
            ResourceRelationship(
                target_resource_id=ResourceId(rel["target_resource_id"]),
                relationship_type=RelationshipType(rel["relationship_type"]),
            )
            for rel in (row.relationships or [])
        ),
        collected_at=row.collected_at,
        account_id=row.account_id,
    )


# ---------------------------------------------------------------------
# Finding snapshot
# ---------------------------------------------------------------------


def finding_to_row(finding: Finding, *, scan_key: str) -> dict[str, Any]:
    return {
        "finding_id": str(finding.id),
        "logical_finding_id": finding.logical_finding_id,
        "scan_key": scan_key,
        "tenant_id": str(finding.tenant_id),
        "account_id": finding.account_id,
        "resource_id": str(finding.resource_id),
        "rule_id": str(finding.rule_id),
        "rule_version": finding.rule_version,
        "framework": finding.framework,
        "control_id": finding.control_id,
        "domain": finding.domain,
        "status": finding.status.value,
        "severity": finding.severity.value,
        # Evidence is rendered from collected attributes and could in
        # principle interpolate a secret — redacted for the same reason.
        "evidence": redact(dict(finding.evidence.data)),
        "detected_at": finding.detected_at,
        "region": finding.region,
        "environment": finding.environment,
        "version": finding.version,
        "superseded_by": str(finding.superseded_by) if finding.superseded_by else None,
        "risk": finding.risk,
        "confidence": finding.confidence,
        "related_attack_path_ids": [str(a) for a in finding.related_attack_path_ids],
        "related_drift_event_ids": list(finding.related_drift_event_ids),
        # Resource identifiers and relationship types only — no attribute
        # values — but routed through redact() anyway, because "this
        # payload cannot contain a secret" is an assumption that a future
        # collector change can silently invalidate.
        "related_resources": list(finding.related_resources),
        "indeterminate_resources": list(finding.indeterminate_resources),
        "graph_context": (
            redact(dict(finding.graph_context)) if finding.graph_context is not None else None
        ),
    }


def finding_to_domain(row: Any) -> Finding:
    return Finding(
        id=FindingId(row.finding_id),
        tenant_id=TenantId(row.tenant_id),
        resource_id=ResourceId(row.resource_id),
        rule_id=RuleId(row.rule_id),
        framework=row.framework,
        control_id=row.control_id,
        domain=row.domain,
        status=FindingStatus(row.status),
        severity=Severity(row.severity),
        evidence=Evidence(data=dict(row.evidence or {})),
        detected_at=row.detected_at,
        scan_id=row.scan_key,
        rule_version=row.rule_version,
        region=row.region,
        environment=row.environment,
        version=row.version,
        superseded_by=FindingId(row.superseded_by) if row.superseded_by else None,
        related_attack_path_ids=tuple(AttackPathId(a) for a in (row.related_attack_path_ids or [])),
        related_drift_event_ids=tuple(row.related_drift_event_ids or []),
        risk=row.risk,
        confidence=row.confidence,
        account_id=row.account_id,
        logical_finding_id=row.logical_finding_id,
        related_resources=tuple(row.related_resources or []),
        indeterminate_resources=tuple(row.indeterminate_resources or []),
        graph_context=row.graph_context,
    )


# ---------------------------------------------------------------------
# Logical finding (lifecycle)
# ---------------------------------------------------------------------


def logical_finding_to_row(lf: LogicalFinding) -> dict[str, Any]:
    return {
        "logical_finding_id": lf.logical_finding_id,
        "tenant_id": str(lf.tenant_id),
        "provider": lf.provider.value,
        "account_id": lf.account_id,
        "resource_id": str(lf.resource_id),
        "rule_id": str(lf.rule_id),
        "state": lf.state.value,
        "severity": lf.severity.value,
        "first_seen_at": lf.first_seen_at,
        "last_seen_at": lf.last_seen_at,
        "first_seen_scan_key": lf.first_seen_scan_key,
        "last_seen_scan_key": lf.last_seen_scan_key,
        "resolved_at": lf.resolved_at,
        "resolved_scan_key": lf.resolved_scan_key,
        "reopen_count": lf.reopen_count,
        "occurrence_count": lf.occurrence_count,
        "suppressed_reason": lf.suppressed_reason,
        "updated_at": _utcnow(),
    }


def logical_finding_to_domain(row: Any) -> LogicalFinding:
    return LogicalFinding(
        logical_finding_id=row.logical_finding_id,
        tenant_id=TenantId(row.tenant_id),
        provider=CloudProvider(row.provider),
        account_id=row.account_id,
        resource_id=ResourceId(row.resource_id),
        rule_id=RuleId(row.rule_id),
        state=LifecycleState(row.state),
        severity=Severity(row.severity),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        first_seen_scan_key=row.first_seen_scan_key,
        last_seen_scan_key=row.last_seen_scan_key,
        resolved_at=row.resolved_at,
        resolved_scan_key=row.resolved_scan_key,
        reopen_count=row.reopen_count,
        occurrence_count=row.occurrence_count,
        suppressed_reason=row.suppressed_reason,
    )


# ---------------------------------------------------------------------
# Rule version metadata
# ---------------------------------------------------------------------


def rule_to_row(rule: Any) -> dict[str, Any]:
    """``domain.rules.rule.Rule`` -> a ``rule_versions`` row.

    Typed loosely to keep this module free of a hard dependency on the
    rule catalog; only documented public attributes are read.
    """

    remediation: Mapping[str, Any] | None = None
    if rule.remediation is not None:
        remediation = {
            "summary": rule.remediation.summary,
            "why_it_matters": rule.remediation.why_it_matters,
            "how_to_fix": rule.remediation.how_to_fix,
            "automation_example": rule.remediation.automation_example,
        }

    return {
        "rule_id": str(rule.id),
        "rule_version": rule.version,
        "title": rule.title,
        "description": rule.description,
        "rationale": rule.rationale,
        "service": rule.service,
        "domain": rule.domain,
        "severity": rule.severity.value,
        "confidence": rule.confidence.value,
        "applies_to_resource_type": rule.applies_to_resource_type,
        "framework": rule.framework,
        "control_id": rule.control_id,
        "remediation": remediation,
        "framework_mappings": [
            {"framework": m.framework, "control": m.control, "status": m.status}
            for m in rule.framework_mappings
        ],
        "references": list(rule.references),
        "tags": list(rule.tags),
        "recorded_at": _utcnow(),
    }


# ---------------------------------------------------------------------
# Attack paths (STEP 4)
# ---------------------------------------------------------------------


def attack_path_fingerprint(path: AttackPath) -> str:
    """Topology hash, excluding score, confidence and provenance.

    So "is this the same path as last week" survives a re-scoring or a
    change to the weights. Only a change in the actual chain — different
    nodes, different edges, different order — changes it.
    """

    material = "|".join(
        [str(path.tenant_id), path.scenario]
        + [str(n.resource_id) for n in path.nodes]
        + [f"{e.source_id}>{e.target_id}:{e.relationship_type.value}" for e in path.edges]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def attack_path_to_row(path: AttackPath, *, scan_key: str, created_at: datetime) -> dict[str, Any]:
    provider = next(
        (n.provider.value for n in path.nodes if n.provider is not None), None
    )
    return {
        "attack_path_id": str(path.id),
        "scan_key": scan_key,
        "tenant_id": str(path.tenant_id),
        "scenario": path.scenario,
        "provider": provider,
        "severity": path.severity.value,
        "risk_score": path.risk_score,
        "confidence": path.confidence,
        "source_id": str(path.entry_point.resource_id),
        "target_id": str(path.target.resource_id),
        "nodes": [
            {
                "resource_id": str(n.resource_id),
                "resource_type": n.resource_type,
                "provider": n.provider.value if n.provider else None,
                "account_id": n.account_id,
                "region": n.region,
                "confidence": n.confidence,
                "kind": n.kind,
            }
            for n in path.nodes
        ],
        "edges": [
            {
                "source": str(e.source_id),
                "target": str(e.target_id),
                "relationship": e.relationship_type.value,
                "blocked": e.blocked,
                "confidence": e.confidence,
                # Redacted for the same reason finding evidence is: this
                # payload is assembled from collected values, and "it
                # cannot contain a secret" is an assumption a future
                # collector change can invalidate.
                "evidence": redact(dict(e.evidence)),
            }
            for e in path.edges
        ],
        "evidence": redact(dict(path.evidence)),
        "contributing_finding_ids": [str(f) for f in path.contributing_finding_ids],
        "algorithm_version": path.algorithm_version,
        "scoring_model_version": path.evidence.get("scoring_model"),
        "fingerprint": attack_path_fingerprint(path),
        "created_at": created_at,
    }


def attack_path_row_to_summary(row: Any) -> dict[str, Any]:
    """A plain mapping for the API layer.

    Deliberately NOT rebuilt into an ``AttackPath``. The aggregate's
    invariants (path integrity, tenant match on every node, blocked
    implies score 0) are construction-time guarantees over live
    ``GraphNode``/``GraphEdge`` objects. Reconstituting those from JSONB
    would either re-validate against a graph that no longer exists, or
    force the invariants to be relaxed — and relaxing an aggregate so it
    can be read back is how an aggregate stops meaning anything.
    """

    return {
        "id": row.attack_path_id,
        "scan_key": row.scan_key,
        "tenant_id": row.tenant_id,
        "scenario": row.scenario,
        "provider": row.provider,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "confidence": row.confidence,
        "source": row.source_id,
        "target": row.target_id,
        "nodes": list(row.nodes or []),
        "edges": list(row.edges or []),
        "evidence": dict(row.evidence or {}),
        "contributing_finding_ids": list(row.contributing_finding_ids or []),
        "algorithm_version": row.algorithm_version,
        "scoring_model_version": row.scoring_model_version,
        "fingerprint": row.fingerprint,
        "created_at": row.created_at,
    }
