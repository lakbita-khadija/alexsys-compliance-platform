# Phase 3B — The Expected-vs-Actual Conformance Framework

> The conformance framework answers one question: **"did the Rule
> Engine get it right?"** It never evaluates a rule itself, and it
> never reads Terraform. It compares a human-declared expectation
> against what the real engine actually produced, and classifies the
> difference.

---

## 1. Why this exists

A rule catalog with passing tests is not the same as a *correct* rule
catalog. The failure modes that matter in a CSPM are:

* **False negative** — a real violation the engine reported as PASS.
  The finding nobody sees.
* **False positive** — a compliant resource the engine flagged. The
  finding nobody trusts, which trains operators to ignore the tool.
* **Silent scope creep** — a rule that starts firing against resources
  it was never meant to judge.

Ordinary unit tests catch the first two only where someone thought to
write the assertion. This framework makes the expectations **data**,
declares them per scenario, runs the **entire** catalog, and classifies
everything that does not match — including things nobody predicted.

---

## 2. The three-component separation

| Component | Job | Never does |
|---|---|---|
| Terraform (`phase-3-terraform.md`) | Create real resources | Know rule ids or expected findings |
| Rule Engine (`phase-3-rules.md`) | Decide compliant / not / unknown | Compare expected to actual |
| **Conformance framework** (this doc) | Compare and classify | Evaluate rules; parse Terraform |

Enforced by tests, not convention:

```python
def test_comparator_does_not_import_the_rule_evaluator(self) -> None:
    imported = self._imported_names(comparator_module)
    assert not any("domain.rules.conditions" in name for name in imported)
    assert not any("evaluate_rules" in name for name in imported)

def test_comparator_never_calls_a_rule_evaluation_function(self) -> None:
    called = self._called_names(comparator_module)
    assert "evaluate_condition" not in called
```

These assert against the module's **parsed AST**, not its source text —
the comparator's own docstring legitimately *names* `evaluate_condition`
in order to state that it never calls it, and a substring check would
flag that documentation as a violation.

---

## 3. The models

`application/conformance/models.py`:

| Model | Meaning |
|---|---|
| `Scenario` | One resource (+ optional graph and neighbours) and the expectations declared against it |
| `ExpectedFinding` | "Rule X should evaluate to status Y" — plus optional severity and evidence assertions |
| `ActualFinding` | A narrow projection of a real `Finding`: rule, resource, status, severity, evidence |
| `ConformanceOutcome` | The closed 10-value classification vocabulary |
| `ConformanceResult` | One classified comparison |
| `ConformanceReport` | Every result for one scenario |

**`ActualFinding` deliberately drops scan-scoped identity** —
`Finding.id`, `scan_id`, `detected_at`. Comparing on physical finding
identity would make every conformance check fail simply because it ran
at a different time, which is not what conformance means.

---

## 4. The outcome vocabulary

| Outcome | Meaning |
|---|---|
| `PASS` | Every declared expectation matched |
| `MISSING_FINDING` | Expected a rule's finding; the catalog produced none (typo, or the rule was removed/renamed) |
| `UNEXPECTED_FINDING` | A rule FAILed against this resource with no expectation declared |
| `WRONG_RULE` | The matched finding is for a different rule |
| `WRONG_RESOURCE` | The finding belongs to a different resource |
| `WRONG_STATUS` | Status differs, and it is not a PASS↔FAIL flip |
| `WRONG_SEVERITY` | Status matched; declared severity did not |
| `WRONG_EVIDENCE` | Status matched; the evidence lacks a declared substring |
| `FALSE_POSITIVE` | Expected PASS, got FAIL — a false alarm |
| `FALSE_NEGATIVE` | Expected FAIL, got PASS — a missed violation |

`FALSE_POSITIVE`/`FALSE_NEGATIVE` are **separated from
`WRONG_STATUS`** on purpose. All three are "the status was wrong", but
only the first two are the security-meaningful failure modes a reviewer
must triage first. A PASS↔INDETERMINATE difference is a data-collection
problem; a PASS↔FAIL difference is a correctness problem.

---

## 5. The comparator — three deterministic passes

`application/conformance/comparator.py`:

1. **Canonicalize.** Index every `ActualFinding` by `rule_id` into a
   dict. Not a list scanned linearly — comparison must never depend on
   the order findings happened to be produced in.
2. **Match by stable key and classify.** For each `ExpectedFinding`,
   look up its `rule_id` and classify: missing → wrong resource →
   wrong rule → status (with the false-positive/negative split) →
   severity → evidence → PASS.
3. **Classify the leftovers.** Any actual finding whose `rule_id` no
   expectation claimed, **and whose status is FAIL**, becomes
   `UNEXPECTED_FINDING`. Unclaimed PASS/INDETERMINATE findings are not
   reported — a scenario about S3 encryption should not have to
   enumerate all 67 other rules.

Two invariants the brief called for, both held:

* **Never `expected == actual`.** Every classification compares
  individually named fields. Dataclass equality would collapse ten
  distinguishable outcomes into one useless boolean.
* **Never ordering-dependent.** Results are sorted by `rule_id` before
  the report is built. A test asserts this directly.

Evidence comparison is **substring containment**, not equality: a
scenario asserts that the narrative mentions the bucket name and the
word "public", not that it matches a full sentence character for
character — which would make every wording improvement a test failure.

---

## 6. The runner

`application/conformance/runner.py` is the thinnest possible glue: it
runs the **real** `EvaluateRules` against the scenario's resource and
hands both sides to the comparator.

Two decisions worth stating:

* **The full catalog runs, never just the expected rule ids.** If it
  were restricted to the rules a scenario mentions, `UNEXPECTED_FINDING`
  would be permanently unreachable — and that outcome is the entire
  point of the exercise.
* **A graph is always supplied**, even for scenarios with no
  relationships (an otherwise-empty graph holding just the scenario's
  own resource). The DSL treats a `relationship` node evaluated without
  a graph as a *caller wiring bug* and raises — correct for the real
  scan path, where `ScanCloudAccount` always builds one. Supplying an
  empty graph gives the semantically right answer instead:
  `neighbors()` returns `()`, which existence-quantifies to
  `NOT_MATCHED` → PASS. *"A bucket with no attached security group does
  not fail 'attached to an open security group'"* is a determinate
  fact, not a missing-data case.

`detected_at` is a fixed module constant, not `datetime.now()` —
conformance runs must be reproducible regardless of wall-clock time.

---

## 7. What this framework caught (twice)

This is not a hypothetical safety net. It found two real defects during
its own construction:

### 7.1 An incomplete fixture

The first run of the S3 scenarios reported:

```
[NON-CONFORMANT] s3-policy-public-bucket (4 rule assertion(s))
    unexpected_finding: s3-bucket-public-access-block-disabled — rule FAILed
    against this resource, but the scenario declared no expectation for it
```

Correct, and the scenario was wrong: Block Public Policy must be off
for a public bucket policy to take effect at all, so that rule
necessarily fires alongside it. A genuine rule interaction, surfaced
by classification rather than by inspection.

### 7.2 A real architectural bug — cross-resource-type rule bleed

The first run of the Azure scenarios reported:

```
[NON-CONFORMANT] azure-storage-open-firewall (4 rule assertion(s))
    unexpected_finding: azure-key-vault-network-default-allow — rule FAILed
    against this resource, but the scenario declared no expectation for it
```

A **Key Vault** rule was firing against a **storage account**. Both
resource types carry an attribute named `network_default_action`, and
rules had no resource-type scoping at all — so every rule was evaluated
against every resource of every type, in both clouds.

The fix was a domain change, not a fixture change:
`Rule.applies_to_resource_type` (`phase-3-rules.md` §6), plus a test
asserting **every shipped rule** declares it. A regression-guard
scenario (`azure-key-vault-does-not-inherit-storage-rules`) now holds
that line.

This bug would have been invisible to per-rule unit tests, because each
rule was individually correct. It was only visible when the *whole
catalog* ran against a resource and something unexpected came back.

---

## 8. The scenarios

`tests/conformance/scenarios/*.yaml` — **54 scenarios, 153 rule
assertions**, all conformant.

| File | Scenarios | Covers |
|---|---|---|
| `s3.yaml` | 6 | ACL vs policy exposure, encryption/versioning composite, uncollected attributes |
| `security_group.yaml` | 6 | Named ports, port ranges, SG→SG chaining (both directions) |
| `ec2.yaml` | 5 | Public IP, IMDSv2, instance-store edge case, VM→SG relationship |
| `iam.yaml` | 9 | Per-user and account-wide, boundary cases, no-password-policy |
| `cloudtrail.yaml` | 5 | Trail config plus destination-bucket relationships |
| `kms.yaml` | 6 | Rotation, key policy, AWS-managed-key null semantics |
| `azure_storage.yaml` | 6 | Anonymous access vs firewall, TLS boundary, uncollected facts |
| `azure_network_compute.yaml` | 11 | NSG ports, VM→NSG relationship, Key Vault, Activity Log→storage |

Scenarios are **synthetic** — the resources are built from the YAML,
not collected from a cloud. Deliberately: it makes the suite runnable
in CI with zero credentials, deterministic regardless of account state,
and fast (0.4s). It validates the **rule catalog**; validating the
**collectors** against a real cloud is the separate, opt-in
`tests/integration/{aws,azure}/` suites' job.

Coverage the scenarios deliberately include:

* **Three-valued logic** — scenarios asserting `INDETERMINATE`, with a
  meta-test asserting such scenarios exist at all, so the invariant
  cannot quietly lose its coverage.
* **Boundary cases** — password length exactly 14, TLS exactly 1.2.
* **Negative controls** — every relationship rule has both a firing and
  a non-firing scenario, proving it actually inspects the neighbour's
  state rather than the mere existence of an edge.

---

## 9. The meta-test

Everything above asserts "the catalog conforms". That is only
meaningful if non-conformance would actually be *caught* — a comparator
hardwired to return `PASS` would satisfy every scenario.

`TestComparatorActuallyDetectsFaults` deliberately corrupts a
known-good scenario and asserts the specific fault is reported:

| Corruption | Must be classified as |
|---|---|
| Flip an expected FAIL to PASS | `FALSE_POSITIVE` |
| Assert FAIL on a compliant resource | `FALSE_NEGATIVE` |
| Expect a nonexistent rule id | `MISSING_FINDING` |
| Declare the wrong severity | `WRONG_SEVERITY` |
| Declare evidence text that isn't there | `WRONG_EVIDENCE` |
| Drop an expectation for a rule that does fire | `UNEXPECTED_FINDING` |

---

## 10. Loading

`infrastructure/conformance/scenario_loader.py` mirrors
`YamlRuleCatalog`'s shape and philosophy: YAML → `Scenario` objects,
nothing more. It never runs a scenario and never classifies anything. A
scenario that doesn't map cleanly onto `Scenario`'s fields fails to
load, loudly.

Relationship declarations are turned into a real `ResourceGraph` plus
the neighbours' full `NormalizedResource`s, so relationship rules
evaluate against genuine graph data rather than a mock.

---

## 11. Known limitations

1. **Scenarios are synthetic.** They validate the rule catalog against
   *declared* resource shapes. If a collector produces a shape nobody
   anticipated, only the integration suites catch it.
2. **Unclaimed PASS findings are not reported.** A scenario cannot
   currently assert "no other rule should PASS here" — only the FAIL
   case is surfaced as unexpected. This is a deliberate
   signal-to-noise choice.
3. **One resource per scenario.** Neighbours exist for relationship
   resolution, but only the primary resource's findings are compared.
4. **No severity/evidence assertion is required.** A scenario asserting
   only status still passes; the framework does not force full
   assertions.
