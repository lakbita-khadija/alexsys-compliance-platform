"""The Compliance Catalog — Rule ↔ Framework ↔ Control (STEP 7).

Two questions, and the catalog exists to answer both:

    Which compliance control does this ComplianceIQ rule assess?
    Which ComplianceIQ rules provide evidence for this control?

**This is a technical mapping layer, not a regulatory corpus.** The
distinction is the most important thing in this module and it decides
what belongs here:

===============================  ==================================
Platform Catalog (this)          AI / RAG corpus (another team)
===============================  ==================================
rule → control mapping           control text, summaries, references
mapping status and provenance    retrieval, citation, explanation
coverage arithmetic              regulatory interpretation
===============================  ==================================

The shared vocabulary is exactly three fields — ``framework``,
``version``, ``control_id`` — used as **reference keys**. A control
appearing in the corpus does not create a mapping here, and a corpus
entry is never evidence that a rule assesses that control. Those are
different claims and only the second is ours to make.

Consequence, deliberate: this module stores **no control titles or
descriptions**. Not an oversight — regulatory text is the corpus's
domain, and reproducing it here would fork it. ``Control.title`` exists
as an optional field so a future integration can populate it from an
authoritative source; nothing in the Platform fabricates one.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping

from domain.rules.rule import (
    MAPPING_PROPOSED,
    MAPPING_UNRESOLVED,
    MAPPING_VERIFIED,
    Rule,
)
from domain.shared.errors import InvalidComplianceData
from domain.shared.identifiers import RuleId

#: Sentinel for "this framework reference records no version".
#:
#: Spelled out rather than left as ``None`` so it survives sorting,
#: grouping and report rendering as a visible fact. A mapping without a
#: version is not auditable — CIS AWS Foundations v1.4.0 and v3.0.0
#: renumber controls — and the reports must be able to say so rather
#: than silently showing a blank.
UNVERSIONED = "unversioned"


@dataclass(frozen=True, slots=True, order=True)
class ControlRef:
    """The reference key shared with the AI corpus. Three fields, no text."""

    framework: str
    version: str
    control_id: str

    def __post_init__(self) -> None:
        for name in ("framework", "version", "control_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidComplianceData(f"ControlRef.{name} must be a non-blank string")

    def __str__(self) -> str:
        return f"{self.framework}@{self.version}:{self.control_id}"


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One rule → control mapping, with its status and provenance."""

    rule_id: RuleId
    control: ControlRef
    status: str
    provenance: str | None = None
    rationale: str | None = None
    #: True when this came from the rule's primary
    #: ``framework``/``control_id`` rather than a ``framework_mappings``
    #: entry. Kept because the primary mapping is what feeds
    #: ``Finding.framework``/``control_id`` and therefore what framework
    #: scoring measures; a secondary mapping contributes to coverage but
    #: not to any score.
    primary: bool = False

    def __post_init__(self) -> None:
        if self.status == MAPPING_VERIFIED and not self.provenance:
            raise InvalidComplianceData(
                f"catalog entry {self.rule_id}→{self.control} claims 'verified' "
                "without provenance"
            )

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identity for duplicate detection: rule + framework + version + control."""

        return (
            str(self.rule_id),
            self.control.framework,
            self.control.version,
            self.control.control_id,
        )


@dataclass(frozen=True, slots=True)
class Control:
    """A control the Platform catalog knows about, and what assesses it."""

    ref: ControlRef
    rule_ids: tuple[RuleId, ...]
    #: Regulatory text is the corpus's domain — see the module docstring.
    title: str | None = None

    @property
    def is_orphan(self) -> bool:
        """No rule provides evidence for this control."""

        return not self.rule_ids


@dataclass(frozen=True, slots=True)
class Framework:
    """A framework the Platform catalog references.

    ``jurisdiction`` and ``authority`` are optional and are populated
    only from the registry below, never guessed from an identifier.
    """

    id: str
    version: str
    jurisdiction: str | None = None
    authority: str | None = None
    name: str | None = None


#: What the Platform knows about the framework identifiers its rules
#: actually use. Facts about the publishing body, not regulatory content.
#:
#: Only identifiers PRESENT IN THE RULE CATALOG appear here. Adding a row
#: for a framework no rule references would manufacture the appearance of
#: coverage, which is the failure mode this whole step exists to avoid.
_FRAMEWORK_FACTS: Mapping[str, tuple[str | None, str | None, str | None]] = {
    # id: (name, jurisdiction, authority)
    "iso_27001": ("ISO/IEC 27001", "International", "ISO/IEC"),
    "cis_aws": ("CIS Amazon Web Services Foundations Benchmark", "International", "Center for Internet Security"),
    "cis_azure": ("CIS Microsoft Azure Foundations Benchmark", "International", "Center for Internet Security"),
    "nist_800_53": ("NIST SP 800-53", "United States", "NIST"),
}

#: Framework versions the Platform can state with a reason.
#:
#: `iso_27001` is the only entry, and the reasoning is recorded because
#: it is an INFERENCE rather than a declaration in the data: the rule
#: catalog's control ids use the `A.5.x`/`A.8.x` structure, which is
#: unambiguously the 2022 revision — the 2013 revision numbered Annex A
#: `A.5` through `A.18` differently.
#:
#: Every other framework stays `UNVERSIONED`. Guessing a CIS benchmark
#: edition from control numbering would be exactly the fabrication the
#: no-invention rule forbids.
_INFERRED_VERSIONS: Mapping[str, str] = {"iso_27001": "2022"}


@dataclass(frozen=True, slots=True)
class ComplianceCatalog:
    """The assembled catalog. Built from rules; never hand-maintained."""

    entries: tuple[CatalogEntry, ...] = ()
    frameworks: tuple[Framework, ...] = ()
    controls: tuple[Control, ...] = ()
    #: Rules carrying no mapping at all. Empty today (every rule has a
    #: primary framework), kept because the arithmetic must not silently
    #: assume that stays true.
    unmapped_rule_ids: tuple[RuleId, ...] = ()
    duplicates: tuple[tuple[str, str, str, str], ...] = ()

    def entries_for_rule(self, rule_id: RuleId | str) -> tuple[CatalogEntry, ...]:
        """Every control this rule maps to — across all frameworks."""

        return tuple(e for e in self.entries if str(e.rule_id) == str(rule_id))

    def rules_for_control(self, control: ControlRef) -> tuple[RuleId, ...]:
        """Every rule providing evidence for this control."""

        return tuple(
            sorted({e.rule_id for e in self.entries if e.control == control}, key=str)
        )

    def controls_for_framework(self, framework: str) -> tuple[Control, ...]:
        return tuple(c for c in self.controls if c.ref.framework == framework)

    def orphan_controls(self) -> tuple[Control, ...]:
        return tuple(c for c in self.controls if c.is_orphan)

    def multi_framework_rules(self) -> tuple[RuleId, ...]:
        """Rules providing evidence across more than one framework."""

        by_rule: dict[str, set[str]] = defaultdict(set)
        for entry in self.entries:
            by_rule[str(entry.rule_id)].add(entry.control.framework)
        return tuple(
            RuleId(rid) for rid in sorted(by_rule) if len(by_rule[rid]) > 1
        )

    def status_counts(self, framework: str | None = None) -> dict[str, int]:
        counts = {MAPPING_VERIFIED: 0, MAPPING_UNRESOLVED: 0, MAPPING_PROPOSED: 0}
        for entry in self.entries:
            if framework is not None and entry.control.framework != framework:
                continue
            counts[entry.status] = counts.get(entry.status, 0) + 1
        return counts


def build_catalog(rules: Iterable[Rule]) -> ComplianceCatalog:
    """Assemble the catalog from the real rule catalog.

    Deterministic: every collection is sorted, so two runs over the same
    rules produce byte-identical output and a diff in a generated report
    means the rules changed.

    Duplicates are **reported, not raised**. A duplicate
    ``(rule, framework, version, control)`` is a catalog hygiene problem
    that a maintainer should see and fix; aborting rule loading over one
    would take the whole product down for a documentation defect. The
    entry list is deduplicated so downstream arithmetic stays correct.
    """

    rules = sorted(rules, key=lambda r: str(r.id))

    seen: dict[tuple[str, str, str, str], CatalogEntry] = {}
    duplicates: list[tuple[str, str, str, str]] = []
    unmapped: list[RuleId] = []

    for rule in rules:
        rule_entries = list(_entries_for(rule))
        if not rule_entries:
            unmapped.append(rule.id)
        for entry in rule_entries:
            if entry.key in seen:
                duplicates.append(entry.key)
                continue
            seen[entry.key] = entry

    entries = tuple(sorted(seen.values(), key=lambda e: (str(e.rule_id), str(e.control))))

    # Controls: every referenced control, with the rules that assess it.
    by_control: dict[ControlRef, set[RuleId]] = defaultdict(set)
    for entry in entries:
        by_control[entry.control].add(entry.rule_id)

    controls = tuple(
        Control(ref=ref, rule_ids=tuple(sorted(rule_ids, key=str)))
        for ref, rule_ids in sorted(by_control.items(), key=lambda kv: str(kv[0]))
    )

    # Frameworks: one row per (id, version) pair actually referenced.
    pairs = sorted({(e.control.framework, e.control.version) for e in entries})
    frameworks = tuple(
        Framework(
            id=fid,
            version=version,
            name=_FRAMEWORK_FACTS.get(fid, (None, None, None))[0],
            jurisdiction=_FRAMEWORK_FACTS.get(fid, (None, None, None))[1],
            authority=_FRAMEWORK_FACTS.get(fid, (None, None, None))[2],
        )
        for fid, version in pairs
    )

    return ComplianceCatalog(
        entries=entries,
        frameworks=frameworks,
        controls=controls,
        unmapped_rule_ids=tuple(sorted(unmapped, key=str)),
        duplicates=tuple(sorted(set(duplicates))),
    )


def _entries_for(rule: Rule) -> Iterable[CatalogEntry]:
    """One rule's mappings: its primary, plus every secondary."""

    # The primary mapping. Status is `unresolved`, not `verified`: it is
    # a required field every rule must fill in, so its presence proves a
    # maintainer typed something, not that anyone checked it against the
    # standard. Marking it verified by default would manufacture
    # exactly the unfalsifiable claim this catalog exists to prevent.
    yield CatalogEntry(
        rule_id=rule.id,
        control=ControlRef(
            framework=rule.framework,
            version=_INFERRED_VERSIONS.get(rule.framework, UNVERSIONED),
            control_id=rule.control_id,
        ),
        status=MAPPING_UNRESOLVED,
        rationale=(
            "Primary rule metadata. Required on every rule, so its presence "
            "records intent rather than verification."
        ),
        primary=True,
    )

    for mapping in rule.framework_mappings:
        yield CatalogEntry(
            rule_id=rule.id,
            control=ControlRef(
                framework=mapping.framework,
                version=mapping.version
                or _INFERRED_VERSIONS.get(mapping.framework, UNVERSIONED),
                control_id=mapping.control,
            ),
            status=mapping.status,
            provenance=mapping.provenance,
            rationale=mapping.rationale,
            primary=False,
        )


# ---------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FrameworkCoverage:
    """Coverage arithmetic for one (framework, version) pair."""

    framework: str
    version: str
    controls: int
    verified: int
    unresolved: int
    proposed: int
    rules_mapped: int
    controls_with_a_verified_mapping: int

    @property
    def coverage(self) -> float:
        """The metric, defined once — see the module note below.

        ``controls with at least one VERIFIED mapping / controls
        represented``.

        Deliberately strict. Counting unresolved mappings would let the
        number rise by asserting things nobody checked, which is how a
        compliance product ends up selling coverage it cannot defend in
        an audit. A 0% here is honest and actionable; an inflated 80% is
        neither.
        """

        if self.controls == 0:
            return 0.0
        return round(100.0 * self.controls_with_a_verified_mapping / self.controls, 1)


def coverage_by_framework(catalog: ComplianceCatalog) -> tuple[FrameworkCoverage, ...]:
    """Per-(framework, version) coverage, sorted and deterministic."""

    result: list[FrameworkCoverage] = []
    for framework in catalog.frameworks:
        scoped = [
            e
            for e in catalog.entries
            if e.control.framework == framework.id and e.control.version == framework.version
        ]
        control_refs = {e.control for e in scoped}
        verified_refs = {e.control for e in scoped if e.status == MAPPING_VERIFIED}

        result.append(
            FrameworkCoverage(
                framework=framework.id,
                version=framework.version,
                controls=len(control_refs),
                verified=sum(1 for e in scoped if e.status == MAPPING_VERIFIED),
                unresolved=sum(1 for e in scoped if e.status == MAPPING_UNRESOLVED),
                proposed=sum(1 for e in scoped if e.status == MAPPING_PROPOSED),
                rules_mapped=len({str(e.rule_id) for e in scoped}),
                controls_with_a_verified_mapping=len(verified_refs),
            )
        )
    return tuple(result)


__all__ = [
    "UNVERSIONED",
    "CatalogEntry",
    "ComplianceCatalog",
    "Control",
    "ControlRef",
    "Framework",
    "FrameworkCoverage",
    "build_catalog",
    "coverage_by_framework",
]
