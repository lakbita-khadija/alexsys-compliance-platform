"""Render the Compliance Catalog matrices (STEP 7).

Both reports are **generated from the rule catalog**, never hand-typed.
That is the point: a coverage number somebody wrote by hand is a claim,
and a compliance product's coverage claims are exactly what an auditor
will pull on first. Regenerating is deterministic, so a diff in a
committed report means the rules changed.

Rendering lives in the application layer rather than in a script so it
can be tested without touching the filesystem, and so the script stays a
three-line entry point.
"""

from __future__ import annotations

from domain.compliance.catalog import (
    ComplianceCatalog,
    coverage_by_framework,
)
from domain.rules.rule import MAPPING_PROPOSED, MAPPING_UNRESOLVED, MAPPING_VERIFIED

#: Product framework priority (STEP 7 §4). Listed here so the coverage
#: report can state the tiers a product manager asked about, INCLUDING
#: the ones with no coverage — a matrix that silently omits DNSSI reads
#: as "not asked", when the truth is "asked, and the answer is zero".
_TIERS: tuple[tuple[str, str, str | None], ...] = (
    ("Tier 1", "ISO/IEC 27001:2022", "iso_27001"),
    ("Tier 1", "DNSSI", None),
    ("Tier 1", "Loi 05-20", None),
    ("Tier 2", "NIST CSF", None),
    ("Tier 3", "SOC 2", None),
)

_STATUS_CELL = {
    MAPPING_VERIFIED: "VERIFIED",
    MAPPING_UNRESOLVED: "UNRESOLVED",
    MAPPING_PROPOSED: "PROPOSED",
}


def _fmt(value: str | None) -> str:
    return value if value else "—"


def render_coverage_report(catalog: ComplianceCatalog) -> str:
    """`docs/reports/compliance-catalog-coverage.md`."""

    coverage = coverage_by_framework(catalog)
    total_rules = len({str(e.rule_id) for e in catalog.entries}) + len(
        catalog.unmapped_rule_ids
    )

    lines: list[str] = [
        "# Compliance Catalog — Coverage",
        "",
        "> **Generated from the rule catalog.** Do not edit by hand —",
        "> run `python scripts/generate_compliance_reports.py`. Every number",
        "> below is computed from `rules/**/*.yaml`; none is typed.",
        "",
        "## Coverage metric",
        "",
        "```",
        "coverage = controls with >= 1 VERIFIED mapping",
        "           / controls represented in the Platform Catalog",
        "```",
        "",
        "Deliberately strict, and worth stating why. Counting `unresolved`",
        "mappings would let the number rise by asserting things nobody",
        "checked — which is how a compliance product ends up selling",
        "coverage it cannot defend in an audit. A 0% here is honest and",
        "actionable; an inflated 80% is neither.",
        "",
        "Note the denominator: **controls**, not rules and not findings.",
        "Sixty-eight rules mapping to seven controls is seven controls of",
        "coverage, not sixty-eight.",
        "",
        "## Frameworks referenced by the rule catalog",
        "",
        "| Framework | Version | Controls | Verified | Unresolved | Proposed | Rules mapped | Coverage |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]

    for row in coverage:
        lines.append(
            f"| `{row.framework}` | {row.version} | {row.controls} | {row.verified} "
            f"| {row.unresolved} | {row.proposed} | {row.rules_mapped} | {row.coverage}% |"
        )

    lines += [
        "",
        "## Product framework priority",
        "",
        "The tiers as asked for, including the ones with no coverage — a",
        "matrix that omitted them would read as *not asked* rather than",
        "*asked, answer zero*.",
        "",
        "| Tier | Framework | Present in Platform | Controls | Coverage |",
        "|---|---|---|---:|---:|",
    ]

    by_id = {row.framework: row for row in coverage}
    for tier, label, framework_id in _TIERS:
        if framework_id and framework_id in by_id:
            row = by_id[framework_id]
            lines.append(
                f"| {tier} | {label} | ✅ `{framework_id}` | {row.controls} | {row.coverage}% |"
            )
        else:
            lines.append(f"| {tier} | {label} | ❌ **absent** | 0 | 0% |")

    lines += [
        "",
        "**On NIST.** The catalog contains `nist_800_53`, which is **not**",
        "the NIST Cybersecurity Framework. NIST SP 800-53 and NIST CSF are",
        "different documents with different structures (`AC-3` versus",
        "`PR.AC-4`). Counting one as the other would be a fabricated",
        "coverage claim, so the tier table above reports NIST CSF as absent",
        "while the framework table reports `nist_800_53` on its own row.",
        "",
        "## Catalog totals",
        "",
        f"- Rules in catalog: **{total_rules}**",
        f"- Mappings (rule → control): **{len(catalog.entries)}**",
        f"- Distinct controls: **{len(catalog.controls)}**",
        f"- Distinct (framework, version) pairs: **{len(catalog.frameworks)}**",
        f"- Rules mapping to more than one framework: **{len(catalog.multi_framework_rules())}**",
        f"- Rules with no mapping at all: **{len(catalog.unmapped_rule_ids)}**",
        f"- Orphan controls (no rule): **{len(catalog.orphan_controls())}**",
        f"- Duplicate mappings: **{len(catalog.duplicates)}**",
        "",
        "## Frameworks",
        "",
        "| Id | Name | Version | Jurisdiction | Authority |",
        "|---|---|---|---|---|",
    ]

    for framework in catalog.frameworks:
        lines.append(
            f"| `{framework.id}` | {_fmt(framework.name)} | {framework.version} "
            f"| {_fmt(framework.jurisdiction)} | {_fmt(framework.authority)} |"
        )

    lines += [
        "",
        "## Controls and the rules that assess them",
        "",
        "| Framework | Version | Control | Rules |",
        "|---|---|---|---:|",
    ]
    for control in catalog.controls:
        lines.append(
            f"| `{control.ref.framework}` | {control.ref.version} "
            f"| `{control.ref.control_id}` | {len(control.rule_ids)} |"
        )

    lines.append("")
    return "\n".join(lines)


def render_rule_mapping_matrix(catalog: ComplianceCatalog) -> str:
    """`docs/reports/compliance-rule-mapping-matrix.md`."""

    frameworks = sorted({f.id for f in catalog.frameworks})
    rule_ids = sorted({str(e.rule_id) for e in catalog.entries} | {
        str(r) for r in catalog.unmapped_rule_ids
    })

    header = "| Rule | " + " | ".join(f"`{f}`" for f in frameworks) + " |"
    divider = "|---|" + "---|" * len(frameworks)

    lines: list[str] = [
        "# Compliance Catalog — Rule → Framework Mapping Matrix",
        "",
        "> **Generated from the rule catalog.** Do not edit by hand —",
        "> run `python scripts/generate_compliance_reports.py`.",
        "",
        "A cell shows the strongest status that rule holds for that",
        "framework; `—` means no mapping. `VERIFIED` requires provenance,",
        "so a cell can only reach it when a maintainer recorded what the",
        "mapping was checked against.",
        "",
        header,
        divider,
    ]

    strength = {MAPPING_VERIFIED: 3, MAPPING_PROPOSED: 2, MAPPING_UNRESOLVED: 1}
    for rule_id in rule_ids:
        cells = []
        entries = catalog.entries_for_rule(rule_id)
        for framework in frameworks:
            scoped = [e for e in entries if e.control.framework == framework]
            if not scoped:
                cells.append("—")
                continue
            best = max(scoped, key=lambda e: strength.get(e.status, 0))
            cells.append(f"{_STATUS_CELL.get(best.status, best.status)}")
        lines.append(f"| `{rule_id}` | " + " | ".join(cells) + " |")

    unmapped = catalog.unmapped_rule_ids
    multi = catalog.multi_framework_rules()

    lines += [
        "",
        "## Gaps this matrix reveals",
        "",
        f"- **Rules with no mapping at all:** {len(unmapped)}"
        + (f" — {', '.join(f'`{r}`' for r in unmapped)}" if unmapped else ""),
        f"- **Rules covering more than one framework:** {len(multi)}",
        f"- **Rules with only their primary (ISO) mapping:** "
        f"{len(rule_ids) - len(multi)}",
        "",
        "The last figure is the honest read of this matrix: every rule has",
        "an ISO reference because the field is required, and fewer than half",
        "carry a second framework. A single-framework rule is not a defect —",
        "it is a coverage gap, and naming it is the point of generating this",
        "table rather than asserting a number.",
        "",
    ]
    return "\n".join(lines)


__all__ = ["render_coverage_report", "render_rule_mapping_matrix"]
