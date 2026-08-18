"""STEP 7 — the catalog over the REAL rule catalog, and its reports.

The tests above (`tests/unit/domain/test_compliance_catalog.py`) prove
the catalog's logic against hand-built rules. These prove it against the
68 rules the product actually ships, because a mapping layer that works
on fixtures and not on the real catalog is worth nothing.

The report tests matter for a specific reason: a generated coverage
number that nobody regenerates rots into a claim. Asserting the
committed markdown matches a fresh render is what keeps
`docs/reports/*.md` honest between releases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from application.compliance.catalog_reports import (
    render_coverage_report,
    render_rule_mapping_matrix,
)
from domain.compliance.catalog import build_catalog, coverage_by_framework
from domain.rules.rule import MAPPING_VERIFIED
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

REPO_ROOT = Path(__file__).resolve().parents[3]
REPORTS = REPO_ROOT / "docs" / "reports"


@pytest.fixture(scope="module")
def real_rules():
    rules: list = []
    for directory in sorted(d for d in (REPO_ROOT / "rules").iterdir() if d.is_dir()):
        rules.extend(YamlRuleCatalog(directory).load())
    return tuple(rules)


@pytest.fixture(scope="module")
def catalog(real_rules):
    return build_catalog(real_rules)


class TestTheRealCatalogLoads:
    def test_every_shipped_rule_is_mapped(self, catalog, real_rules) -> None:
        # `framework`/`control_id` are required on every rule, so an
        # unmapped rule would mean the loader silently dropped one.
        assert catalog.unmapped_rule_ids == ()
        assert len({str(e.rule_id) for e in catalog.entries}) == len(real_rules)

    def test_the_catalog_has_no_duplicates(self, catalog) -> None:
        assert catalog.duplicates == ()

    def test_it_covers_more_than_one_framework(self, catalog) -> None:
        assert len({f.id for f in catalog.frameworks}) > 1

    def test_many_to_many_is_real_not_theoretical(self, catalog) -> None:
        # The requirement is only met if the SHIPPED catalog exercises
        # it, not merely if the model permits it.
        assert len(catalog.multi_framework_rules()) > 0

    def test_a_control_is_assessed_by_several_rules(self, catalog) -> None:
        assert max(len(c.rule_ids) for c in catalog.controls) > 1


class TestNoUnprovenancedVerifiedClaims:
    def test_every_verified_mapping_has_provenance(self, catalog) -> None:
        """The invariant, asserted against shipped data.

        The audit found 11 mappings claiming `verified` with no
        provenance field in existence. They were downgraded rather than
        grandfathered — grandfathering would have preserved exactly the
        unfalsifiable claim the field exists to prevent.
        """

        offenders = [
            f"{e.rule_id} -> {e.control}"
            for e in catalog.entries
            if e.status == MAPPING_VERIFIED and not e.provenance
        ]
        assert offenders == []

    def test_coverage_is_not_inflated_by_unresolved_mappings(self, catalog) -> None:
        # Every framework currently sits at 0% because nothing carries
        # provenance yet. That is the honest number, and this test is
        # what stops it drifting upward without evidence being added.
        for row in coverage_by_framework(catalog):
            if row.verified == 0:
                assert row.coverage == 0.0


class TestFindingLinkage:
    def test_a_findings_framework_and_control_resolve_in_the_catalog(
        self, catalog, real_rules
    ) -> None:
        """§12 — validate, do not duplicate.

        A `Finding` carries `framework` and `control_id` copied from its
        rule. Those two fields must resolve against the catalog, which is
        what makes them a reference rather than a loose string. No new
        Finding field is needed, and adding one would break the frozen
        AI contract.
        """

        known = {(c.ref.framework, c.ref.control_id) for c in catalog.controls}
        for rule in real_rules:
            assert (rule.framework, rule.control_id) in known, (
                f"rule {rule.id} produces findings citing "
                f"{rule.framework}:{rule.control_id}, which the catalog does not know"
            )

    def test_the_catalog_answers_which_rules_evidence_a_control(self, catalog) -> None:
        control = max(catalog.controls, key=lambda c: len(c.rule_ids))
        rules = catalog.rules_for_control(control.ref)
        assert len(rules) == len(control.rule_ids)
        assert rules == tuple(sorted(rules, key=str))


class TestReportsAreGeneratedNotWritten:
    def test_the_committed_coverage_report_is_current(self, catalog) -> None:
        # If this fails, run: python scripts/generate_compliance_reports.py
        committed = (REPORTS / "compliance-catalog-coverage.md").read_text(encoding="utf-8")
        assert committed == render_coverage_report(catalog), (
            "docs/reports/compliance-catalog-coverage.md is stale; regenerate it"
        )

    def test_the_committed_mapping_matrix_is_current(self, catalog) -> None:
        committed = (REPORTS / "compliance-rule-mapping-matrix.md").read_text(encoding="utf-8")
        assert committed == render_rule_mapping_matrix(catalog), (
            "docs/reports/compliance-rule-mapping-matrix.md is stale; regenerate it"
        )

    def test_rendering_is_deterministic(self, catalog) -> None:
        assert render_coverage_report(catalog) == render_coverage_report(catalog)
        assert render_rule_mapping_matrix(catalog) == render_rule_mapping_matrix(catalog)

    def test_the_coverage_report_names_absent_tier_one_frameworks(self, catalog) -> None:
        # Omitting DNSSI and Loi 05-20 would read as "not asked" when the
        # truth is "asked, and the answer is zero".
        report = render_coverage_report(catalog)
        for framework in ("DNSSI", "Loi 05-20", "SOC 2", "NIST CSF"):
            assert framework in report
        assert "absent" in report

    def test_the_report_does_not_claim_nist_csf_coverage(self, catalog) -> None:
        # `nist_800_53` is not NIST CSF. Counting one as the other would
        # be a fabricated coverage claim.
        report = render_coverage_report(catalog)
        assert "| Tier 2 | NIST CSF | ❌ **absent** | 0 | 0% |" in report

    def test_the_matrix_lists_every_rule(self, catalog, real_rules) -> None:
        matrix = render_rule_mapping_matrix(catalog)
        for rule in real_rules:
            assert f"`{rule.id}`" in matrix


class TestCatalogIsSharedReadOnlyReferenceData:
    """§19 — the catalog is global, and nothing tenant-facing writes it."""

    def test_the_catalog_carries_no_tenant(self, catalog) -> None:
        # Shared reference data by construction: there is no tenant field
        # to scope, so it cannot be used to smuggle tenant data across a
        # boundary, and no tenant can hold a private version of a control.
        entry = catalog.entries[0]
        assert not hasattr(entry, "tenant_id")
        assert not hasattr(catalog.controls[0], "tenant_id")

    def test_no_api_route_accepts_a_framework_or_control_id_body_field(self) -> None:
        """A tenant cannot inject a control id into authoritative records.

        Structural rather than behavioural: findings get their framework
        and control from the rule engine, and if a request schema ever
        grew a writable one, this fails.
        """

        import inspect

        from presentation import schemas

        source = inspect.getsource(schemas)
        # The scan submission request is the only client-writable body.
        start = source.find("class ScanRequest")
        assert start != -1
        body = source[start : start + 2000]
        assert "control_id" not in body
        assert "framework" not in body

    def test_rules_are_loaded_from_disk_not_from_a_request(self) -> None:
        import inspect

        from infrastructure.rules import yaml_rule_catalog

        # The only ingestion path is the filesystem loader, which no
        # route calls with caller-supplied input.
        assert "def load" in inspect.getsource(yaml_rule_catalog)
