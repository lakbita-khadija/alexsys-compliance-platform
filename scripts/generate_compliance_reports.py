"""Regenerate the Compliance Catalog matrices from the rule catalog.

    python scripts/generate_compliance_reports.py

Writes `docs/reports/compliance-catalog-coverage.md` and
`docs/reports/compliance-rule-mapping-matrix.md`.

Deterministic: running it twice over unchanged rules produces
byte-identical files, so a diff means the rules changed rather than that
the generator did. A test asserts the committed reports match a fresh
regeneration, which is what stops them drifting into fiction.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from application.compliance.catalog_reports import (  # noqa: E402
    render_coverage_report,
    render_rule_mapping_matrix,
)
from domain.compliance.catalog import build_catalog  # noqa: E402
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog  # noqa: E402

#: Every provider directory under `rules/`. Discovered rather than
#: hardcoded, so adding `rules/gcp/` later needs no edit here.
RULES_ROOT = REPO_ROOT / "rules"
REPORTS = REPO_ROOT / "docs" / "reports"


def load_all_rules():
    directories = sorted(d for d in RULES_ROOT.iterdir() if d.is_dir())
    rules: list = []
    for directory in directories:
        rules.extend(YamlRuleCatalog(directory).load())
    return tuple(rules)


def main() -> int:
    catalog = build_catalog(load_all_rules())

    outputs = {
        REPORTS / "compliance-catalog-coverage.md": render_coverage_report(catalog),
        REPORTS / "compliance-rule-mapping-matrix.md": render_rule_mapping_matrix(catalog),
    }
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")

    print(
        f"\n{len(catalog.entries)} mappings · {len(catalog.controls)} controls · "
        f"{len(catalog.frameworks)} (framework, version) pairs"
    )
    if catalog.duplicates:
        print(f"WARNING: {len(catalog.duplicates)} duplicate mapping(s)")
    if catalog.unmapped_rule_ids:
        print(f"WARNING: {len(catalog.unmapped_rule_ids)} rule(s) with no mapping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
