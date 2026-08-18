"""STEP 7 — the Compliance Catalog.

The catalog answers two questions and both matter commercially:

    Which control does this rule assess?
    Which rules provide evidence for this control?

The tests that carry weight here are not the ones checking that a
mapping loads. They are the ones asserting the catalog **cannot inflate
its own coverage**:

* `verified` requires provenance, so a maintainer cannot assert
  compliance coverage without recording what they checked;
* an AI-corpus entry never creates a mapping, because the corpus is
  knowledge and the catalog is a technical claim;
* coverage counts *controls*, not rules or findings, so 68 rules
  pointing at 7 controls is 7 controls of coverage.

A compliance product's coverage number is the first thing an auditor
pulls on. Every guard here exists so that number can be defended.
"""

from __future__ import annotations

import pytest

from domain.compliance.catalog import (
    UNVERSIONED,
    CatalogEntry,
    ControlRef,
    build_catalog,
    coverage_by_framework,
)
from domain.rules.rule import (
    MAPPING_PROPOSED,
    MAPPING_UNRESOLVED,
    MAPPING_VERIFIED,
    FrameworkMapping,
    Rule,
)
from domain.shared.enums import Severity
from domain.shared.errors import InvalidComplianceData, InvalidRule
from domain.shared.identifiers import RuleId

PROVENANCE = "CIS AWS Foundations Benchmark v1.5.0, section 2.1.5"


def rule(
    rule_id="s3-bucket-public",
    *,
    framework="iso_27001",
    control_id="A.8.24",
    mappings=(),
):
    return Rule(
        id=RuleId(rule_id),
        framework=framework,
        control_id=control_id,
        domain="storage",
        severity=Severity.CRITICAL,
        condition={"field": "public", "operator": "is_true"},
        framework_mappings=tuple(mappings),
    )


def mapping(framework="cis_aws", control="2.1.5", **kw):
    return FrameworkMapping(framework=framework, control=control, **kw)


class TestFrameworkRegistryLoads:
    def test_a_catalog_is_built_from_rules(self) -> None:
        catalog = build_catalog([rule()])
        assert len(catalog.entries) == 1
        assert catalog.frameworks[0].id == "iso_27001"

    def test_framework_facts_are_attached(self) -> None:
        framework = build_catalog([rule()]).frameworks[0]
        assert framework.authority == "ISO/IEC"
        assert framework.jurisdiction == "International"

    def test_an_unknown_framework_gets_no_invented_facts(self) -> None:
        # A framework the Platform has never heard of must not acquire a
        # plausible-looking authority from string similarity.
        catalog = build_catalog([rule(framework="some_internal_baseline")])
        assert catalog.frameworks[0].authority is None
        assert catalog.frameworks[0].name is None

    def test_framework_version_pairs_are_unique(self) -> None:
        catalog = build_catalog([rule(), rule("other-rule")])
        pairs = [(f.id, f.version) for f in catalog.frameworks]
        assert len(pairs) == len(set(pairs))


class TestVersions:
    def test_iso_gets_its_inferred_version(self) -> None:
        # Inferred from the A.5.x/A.8.x numbering, which is unambiguously
        # the 2022 revision. The inference is recorded in the source.
        assert build_catalog([rule()]).frameworks[0].version == "2022"

    def test_an_unknown_framework_is_marked_unversioned(self) -> None:
        # Never guessed. A CIS benchmark edition inferred from control
        # numbering would be exactly the fabrication the rules forbid.
        catalog = build_catalog([rule(mappings=[mapping()])])
        cis = next(f for f in catalog.frameworks if f.id == "cis_aws")
        assert cis.version == UNVERSIONED

    def test_an_explicit_mapping_version_is_honoured(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping(version="v1.5.0", status=MAPPING_UNRESOLVED)])]
        )
        cis = next(f for f in catalog.frameworks if f.id == "cis_aws")
        assert cis.version == "v1.5.0"


class TestVerifiedRequiresProvenance:
    """The rule that makes `verified` mean anything."""

    def test_verified_without_provenance_is_rejected_at_the_rule(self) -> None:
        with pytest.raises(InvalidRule, match="provenance"):
            FrameworkMapping(framework="cis_aws", control="2.1.5", status=MAPPING_VERIFIED)

    def test_verified_with_provenance_is_accepted(self) -> None:
        m = mapping(status=MAPPING_VERIFIED, provenance=PROVENANCE)
        assert m.status == MAPPING_VERIFIED

    def test_verified_without_provenance_is_rejected_at_the_catalog_entry(self) -> None:
        # Belt and braces: the entry is constructible from sources other
        # than a Rule, so it enforces the invariant itself.
        with pytest.raises(InvalidComplianceData, match="provenance"):
            CatalogEntry(
                rule_id=RuleId("r"),
                control=ControlRef("cis_aws", UNVERSIONED, "2.1.5"),
                status=MAPPING_VERIFIED,
            )

    def test_provenance_survives_into_the_catalog(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping(status=MAPPING_VERIFIED, provenance=PROVENANCE)])]
        )
        verified = [e for e in catalog.entries if e.status == MAPPING_VERIFIED]
        assert verified[0].provenance == PROVENANCE


class TestStatusesAreDistinct:
    def test_unresolved_stays_unresolved(self) -> None:
        catalog = build_catalog([rule(mappings=[mapping(status=MAPPING_UNRESOLVED)])])
        secondary = [e for e in catalog.entries if not e.primary]
        assert secondary[0].status == MAPPING_UNRESOLVED

    def test_proposed_stays_proposed(self) -> None:
        # `proposed` is not a weaker `verified`. It says a deliberate
        # technical proposal exists, which is a different claim from
        # "nobody checked" — and an auditor treats them differently.
        catalog = build_catalog([rule(mappings=[mapping(status=MAPPING_PROPOSED)])])
        secondary = [e for e in catalog.entries if not e.primary]
        assert secondary[0].status == MAPPING_PROPOSED

    def test_proposed_needs_no_provenance(self) -> None:
        assert mapping(status=MAPPING_PROPOSED).provenance is None

    def test_an_unknown_status_is_rejected(self) -> None:
        with pytest.raises(InvalidRule):
            mapping(status="probably_fine")

    def test_the_primary_mapping_is_never_auto_verified(self) -> None:
        """The single most inflation-prone shortcut, refused.

        Every rule must fill in `framework`/`control_id`, so their
        presence proves a maintainer typed something — not that anyone
        checked it against the standard. Treating a required field as
        evidence would hand the product 100% coverage for free.
        """

        catalog = build_catalog([rule()])
        primary = [e for e in catalog.entries if e.primary]
        assert primary[0].status == MAPPING_UNRESOLVED


class TestManyToMany:
    def test_one_rule_maps_to_many_frameworks(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping("cis_aws", "2.1.5"), mapping("nist_800_53", "AC-3")])]
        )
        frameworks = {e.control.framework for e in catalog.entries}
        assert frameworks == {"iso_27001", "cis_aws", "nist_800_53"}

    def test_one_rule_maps_to_many_controls(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping("cis_aws", "2.1.1"), mapping("cis_aws", "2.1.5")])]
        )
        cis_controls = {
            e.control.control_id for e in catalog.entries if e.control.framework == "cis_aws"
        }
        assert cis_controls == {"2.1.1", "2.1.5"}

    def test_one_control_is_assessed_by_many_rules(self) -> None:
        catalog = build_catalog(
            [rule("rule-a"), rule("rule-b"), rule("rule-c")]
        )
        ref = ControlRef("iso_27001", "2022", "A.8.24")
        assert len(catalog.rules_for_control(ref)) == 3

    def test_one_framework_covers_many_rules(self) -> None:
        catalog = build_catalog([rule("rule-a"), rule("rule-b")])
        iso = [e for e in catalog.entries if e.control.framework == "iso_27001"]
        assert len({str(e.rule_id) for e in iso}) == 2

    def test_multi_framework_rules_are_identifiable(self) -> None:
        catalog = build_catalog(
            [rule("multi", mappings=[mapping()]), rule("single")]
        )
        assert [str(r) for r in catalog.multi_framework_rules()] == ["multi"]


class TestDuplicatesAndOrphans:
    def test_a_duplicate_mapping_is_detected(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping("cis_aws", "2.1.5"), mapping("cis_aws", "2.1.5")])]
        )
        assert len(catalog.duplicates) == 1

    def test_a_duplicate_is_deduplicated_not_double_counted(self) -> None:
        # Reported so a maintainer fixes it, deduplicated so the
        # arithmetic downstream stays correct. Counting it twice would
        # inflate the mapping total for a copy-paste error.
        catalog = build_catalog(
            [rule(mappings=[mapping("cis_aws", "2.1.5"), mapping("cis_aws", "2.1.5")])]
        )
        cis = [e for e in catalog.entries if e.control.framework == "cis_aws"]
        assert len(cis) == 1

    def test_a_duplicate_does_not_raise(self) -> None:
        # Catalog hygiene is a documentation defect. Aborting rule
        # loading over one would take the product down for it.
        build_catalog([rule(mappings=[mapping(), mapping()])])

    def test_the_same_control_in_two_versions_is_not_a_duplicate(self) -> None:
        # Different editions renumber; they are genuinely different
        # controls and must both be represented.
        catalog = build_catalog(
            [
                rule(
                    mappings=[
                        mapping(version="v1.5.0"),
                        mapping(version="v3.0.0"),
                    ]
                )
            ]
        )
        assert catalog.duplicates == ()
        assert len([e for e in catalog.entries if e.control.framework == "cis_aws"]) == 2

    def test_orphan_controls_are_detectable(self) -> None:
        # Nothing in a rule-derived catalog can be orphaned by
        # construction — every control exists because a rule referenced
        # it. The query is here for a future catalog that also ingests a
        # control list, and this pins that it returns nothing today
        # rather than silently reporting a wrong number.
        assert build_catalog([rule()]).orphan_controls() == ()

    def test_rules_without_mappings_are_reported(self) -> None:
        catalog = build_catalog([])
        assert catalog.unmapped_rule_ids == ()


class TestCoverageArithmetic:
    def test_coverage_is_zero_without_verified_mappings(self) -> None:
        catalog = build_catalog([rule(mappings=[mapping(status=MAPPING_UNRESOLVED)])])
        cis = next(c for c in coverage_by_framework(catalog) if c.framework == "cis_aws")
        assert cis.coverage == 0.0

    def test_proposed_does_not_count_as_coverage(self) -> None:
        # A proposal is not evidence.
        catalog = build_catalog([rule(mappings=[mapping(status=MAPPING_PROPOSED)])])
        cis = next(c for c in coverage_by_framework(catalog) if c.framework == "cis_aws")
        assert cis.coverage == 0.0

    def test_a_verified_mapping_produces_coverage(self) -> None:
        catalog = build_catalog(
            [rule(mappings=[mapping(status=MAPPING_VERIFIED, provenance=PROVENANCE)])]
        )
        cis = next(c for c in coverage_by_framework(catalog) if c.framework == "cis_aws")
        assert cis.coverage == 100.0

    def test_coverage_counts_controls_not_rules(self) -> None:
        """The denominator that gets confused, pinned.

        Three rules all pointing at one control is ONE control of
        coverage. Counting rules would let coverage rise by adding rules
        that assess something already assessed.
        """

        catalog = build_catalog([rule("a"), rule("b"), rule("c")])
        iso = next(c for c in coverage_by_framework(catalog) if c.framework == "iso_27001")
        assert iso.controls == 1
        assert iso.rules_mapped == 3

    def test_partial_coverage_is_computed_per_control(self) -> None:
        catalog = build_catalog(
            [
                rule("a", mappings=[mapping("cis_aws", "1.1", status=MAPPING_VERIFIED, provenance=PROVENANCE)]),
                rule("b", mappings=[mapping("cis_aws", "1.2")]),
            ]
        )
        cis = next(c for c in coverage_by_framework(catalog) if c.framework == "cis_aws")
        assert cis.controls == 2
        assert cis.controls_with_a_verified_mapping == 1
        assert cis.coverage == 50.0


class TestDeterminism:
    def test_the_catalog_is_stable_across_runs(self) -> None:
        rules = [rule("b", mappings=[mapping()]), rule("a")]
        runs = [
            [(str(e.rule_id), str(e.control), e.status) for e in build_catalog(rules).entries]
            for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)

    def test_input_order_does_not_matter(self) -> None:
        rules = [rule("b", mappings=[mapping()]), rule("a")]
        forward = [(str(e.rule_id), str(e.control)) for e in build_catalog(rules).entries]
        backward = [
            (str(e.rule_id), str(e.control))
            for e in build_catalog(list(reversed(rules))).entries
        ]
        assert forward == backward

    def test_coverage_is_stable(self) -> None:
        rules = [rule("a"), rule("b", mappings=[mapping()])]
        first = [(c.framework, c.coverage) for c in coverage_by_framework(build_catalog(rules))]
        second = [(c.framework, c.coverage) for c in coverage_by_framework(build_catalog(rules))]
        assert first == second


class TestTheAiCorpusBoundary:
    """§11 — a corpus entry is knowledge, not a technical mapping.

    The corpus does not exist in this repository yet. That is exactly
    why this test is written now: when it lands, the shared
    `framework`/`control_id` keys will make it tempting to promote a
    mapping on the strength of a corpus row. These pin that the catalog
    is built from RULES and nothing else.
    """

    def test_the_catalog_module_can_read_nothing(self) -> None:
        """Structural, via AST — not a grep over prose.

        The module's own docstring discusses the corpus at length, which
        is exactly right and would defeat a text search. What matters is
        the executable code: the catalog imports no I/O and calls no
        loader, so it *cannot* consume a corpus file even by accident.
        If someone later adds one, this fails and forces a deliberate
        decision about what the catalog is allowed to trust.
        """

        import ast
        import inspect

        from domain.compliance import catalog as catalog_module

        tree = ast.parse(inspect.getsource(catalog_module))

        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        for io_module in ("json", "pathlib", "os", "io", "csv", "yaml", "requests"):
            assert io_module not in imported, (
                f"the catalog module imports {io_module!r}; it must be built from "
                "Rule objects only, never by reading the AI corpus or any file"
            )

        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "open" not in called

    def test_a_control_id_alone_creates_no_mapping(self) -> None:
        # Knowing a control exists is not evidence that any rule
        # assesses it. Without a rule referencing it, it is not in the
        # catalog at all.
        catalog = build_catalog([rule()])
        assert ControlRef("dnssi", "unversioned", "DNSSI-ACC") not in {
            c.ref for c in catalog.controls
        }

    def test_a_corpus_shaped_reference_does_not_become_verified(self) -> None:
        # Even when a rule references a corpus-style control id, the
        # mapping's status comes from the rule catalog's own claim —
        # defaulting to unresolved — never from the id looking official.
        catalog = build_catalog([rule(mappings=[mapping("dnssi", "DNSSI-ACC")])])
        entry = next(e for e in catalog.entries if e.control.framework == "dnssi")
        assert entry.status == MAPPING_UNRESOLVED
        assert entry.provenance is None
