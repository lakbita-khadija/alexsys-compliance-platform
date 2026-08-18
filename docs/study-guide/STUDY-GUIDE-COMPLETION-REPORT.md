# Study Guide — Completion Report

---

## 1. No application code was modified

Verified by `git status` after generation:

```
?? docs/study-guide/README.md
?? docs/study-guide/glossary.md
?? docs/study-guide/next-work.md
?? docs/study-guide/phase-00-project-map/
   … 12 more phase directories
```

**Every entry is `??` (untracked) and every path is under
`docs/study-guide/`.** Nothing modified, nothing deleted.

Confirmed independently by re-running the gates after generation:

```
1348 passed, 60 skipped, 0 failed
ruff check .          → All checks passed!
mypy (175 files)      → Success: no issues found
```

Identical to the pre-generation baseline. No Python, YAML rule, test,
schema, migration or configuration file was touched.

---

## 2. Files generated — 35

| Location | Files |
|---|---|
| Root | `README.md`, `glossary.md`, `next-work.md`, this report |
| `phase-00-project-map/` | README, answers |
| `phase-01-cloud-collection/` | README, answers |
| `phase-02-normalization/` | README, answers |
| **`phase-03-resource-graph/`** ★ | README, answers, **3 deep dives** |
| `phase-04-rule-engine/` | README, answers |
| `phase-05-cspm-rules/` | README, answers |
| `phase-06-findings/` | README, answers |
| `phase-07-graph-queries/` | README, answers |
| **`phase-08-attack-paths/`** ★ | README, answers, **3 deep dives** |
| `phase-09-scan-pipeline/` | README, answers |
| `phase-10-frameworks/` | README, answers |
| `phase-11-testing/` | README, answers |
| `phase-12-final-architecture/` | README, answers |

*(`docs/study-guide/phase-3-rules-terraform-conformance.md` pre-existed
and was not modified.)*

### Structural adaptation, and why

The brief sketched ~90 thin topic files and explicitly permitted
adjustment: *"You may adjust the exact number of files if the repository
structure suggests a better organization, but preserve the phase-based
learning progression."*

**13 phases were preserved.** Rather than fragmenting each into 5–10
files of a few paragraphs, each phase is one substantial README carrying
the full A–M teaching structure, with **dedicated deep-dive files only in
the two phases the brief marked for depth** (Resource Graph, Attack
Paths). Every topic the brief listed is covered — the section headings
inside each README map onto the requested filenames.

The trade-off: fewer files, each dense enough to teach from, and no
navigation overhead between four-paragraph fragments.

---

## 3. Diagrams — 34 Mermaid blocks

All verified programmatically: **balanced code fences**, and every block
opens with a valid diagram header (`flowchart`, `sequenceDiagram`,
`classDiagram`).

| Requested (brief §2) | Delivered in |
|---|---|
| 1. Complete pipeline | Phase 0 §E, Phase 12 §1 |
| 2. Cloud collection | Phase 1 §D |
| 3. Resource Graph | Phase 3 §3.1, §3.5 |
| 4. Node vs Edge | Phase 3.1 (`classDiagram`, real fields) |
| 5. Graph query | Phase 7 §D |
| 6. YAML rule → Finding | Phase 4 §D |
| 7. UNKNOWN tri-state | Phase 4 §F, §G |
| 8. Attack Path | Phase 8 §8.5, Phase 8.1 (per scenario) |
| 9. Attack Path scoring | Phase 8.2 |
| 10. Finding ↔ Attack Path | Phase 8.3 |
| 11. Full scan sequence | Phase 9 §C (`sequenceDiagram`) |

Plus: layer dependencies, the seam problem, security flow, roadmap, and a
`next-work` ordering graph.

**No decorative diagrams.** Each explains an architectural or logical
relationship, and every relationship drawn is one the implementation
actually emits — unsupported ones are marked as such.

---

## 4. Concepts and components covered

**Every area the brief listed:** Resource Graph · graph queries ·
cross-resource relationships · AWS/Azure collectors · normalization ·
YAML rules · rule engine · UNKNOWN tri-state · resilience/retry/
pagination · semantic IAM analysis · finding generation · risk enrichment
· attack path analysis · attack path scoring · framework integration
status · scan orchestration · pipeline integration · tests and
architectural guarantees.

**Repository components documented by real path:** `domain/` (graph,
rules, findings, attack_paths, risk, compliance, shared) · `application/`
(scanning, graph, rules, attack_paths, risk) · `infrastructure/`
(cloud/aws, cloud/azure, resilience, policy_analysis, persistence, rules)
· `presentation/` · `rules/` · `tests/` · `scripts/`.

**Every phase ends with** 5–10 learning objectives and 6–9 self-test
questions, with answers in a separate `answers.md`.

---

## 5. Verification performed

| # | Check | Result |
|---|---|---|
| 1 | Every phase directory exists | ✅ 13/13 |
| 2 | Every phase has a README | ✅ 13/13 |
| 3 | Every phase has `answers.md` | ✅ 13/13 |
| 4 | Mermaid fences balanced, headers valid | ✅ 34/34 |
| 5 | No source code modified | ✅ `git status` clean outside the guide |
| 6 | No YAML rules modified | ✅ |
| 7 | No tests modified | ✅ suite unchanged at 1348 passed |
| 8 | Referenced file paths exist | ✅ (see §6) |
| 9 | No fabricated framework references | ✅ counts parsed from the catalog |
| 10 | No unsupported attack path presented as implemented | ✅ status table in Phase 8 §8.11 |

### How the numbers were obtained

Every figure was produced by **executing a command**, not recalled:

| Figure | Source |
|---|---|
| 1408 / 1348 / 60 / 0 | `pytest --collect-only`, `pytest -q` |
| 175 source files | `mypy` output |
| 68 rules, 41/27 split | parsing `rules/**/*.yaml` |
| 7 cross-resource rules | walking every condition tree for a `relationship` node |
| Severity/domain distribution | parsing the catalog |
| 7 ISO controls, 11/27 verified | parsing `framework_mappings` |
| 5 of 8 relationships emitted | grepping `RelationshipType.` in `infrastructure/cloud/` |
| 13 resource types | grepping `resource_type="…"` |
| Benchmark table | running `scripts/benchmark_graph.py` |
| Attack path scores | running the analyzer on a real estate |

---

## 6. Errors found and corrected during verification

**One factual error in the guide, caught by automated path checking:**

`infrastructure/cloud/aws/resilience.py` — **wrong**. The real path is
`infrastructure/cloud/resilience.py`: the resilience layer sits one level
up, shared across providers rather than being AWS-specific. Corrected in
both the prose and the directory tree in Phase 1.

Worth recording, because it is the same failure mode the guide warns
about elsewhere: a plausible-sounding path asserted from memory rather
than checked. The automated verification existed precisely to catch it.

**Four remaining "missing" paths are intentional** — prospective RDS files
inside the answer to *"where would you add an RDS collector?"*. They are
now explicitly labelled *"none of these files exist — this is the
prospective shape"* so no skimming reader mistakes them for real.

---

## 7. Known gaps in the guide itself

1. **No `diagrams/` subdirectories.** The brief sketched them; all
   diagrams are inline Mermaid instead, which renders directly in
   GitHub/IDE preview and keeps each diagram beside the prose explaining
   it. No separate image assets were generated.

2. **Presentation/API layer is covered thinly.** Phases focus on the
   collection→graph→rules→findings→attack-paths chain the brief
   emphasised. The FastAPI layer, JWT/JWKS and persistence internals are
   referenced but not given their own phase — they are documented in
   `docs/architecture/phase-4-*` and `phase-5-*`.

3. **Drift detection is mentioned, not taught.** `DetectDrift` appears in
   the pipeline diagrams; no phase covers `DiffEngine` in depth.

4. **One claim is marked ⚠️ unverified**: whether any API response schema
   exposes `framework_mappings` (Phase 10 answer 4). It is flagged rather
   than guessed.

5. **Estimated study times are judgement, not measurement.**

---

## 8. Gaps in the *product*, surfaced by writing the guide

Documenting forced questions the code had not been asked. Two genuine
findings, both recorded in `next-work.md` rather than fixed (this was a
documentation task):

- **No test asserts that every `RelationshipType` appears in exactly one
  of the traversable/informational sets** (P2.2). Adding a relationship
  type and forgetting to classify it makes attack paths **silently** never
  route through it — no error, no warning. A ten-minute test.

- **`Finding.related_resources` / `graph_context` are computed,
  validated and persisted — and no API schema exposes them** (P2.3). The
  context reaches the database and stops.

---

## 9. Summary

```
Phases:              13  (plus root README, glossary, next-work, this report)
Files generated:     35
Mermaid diagrams:    34   (all validated)
Self-test questions: ~90  (answers in per-phase answers.md)
Estimated study:     ~23 hours

Application code modified:  0 files
Tests modified:             0 files
YAML rules modified:        0 files
Suite after generation:     1348 passed · 60 skipped · 0 failed
ruff:                       clean
mypy:                       clean, 175 source files
```

**No application code was modified.**
