# Phase 10 — Answers

**1. `framework: iso27001` (typo) — what happens?**

- **At load:** nothing. `Rule.framework` is a non-blank string and
  `iso27001` qualifies. No registry validates it. The rule loads cleanly.
- **At evaluation:** nothing. The evaluator never reads `framework`.
  Findings are produced normally, carrying `framework="iso27001"`.
- **In the report:** the damage. `ComplianceScore` groups by framework
  **string**, so this rule's findings land in a *separate* framework
  bucket. The customer's ISO 27001 posture silently omits one rule, and a
  phantom "iso27001" framework appears with a single rule's results.

Three layers, zero errors, one wrong compliance report. This is why "no
framework registry" is the first item in the recommendations.

**2. Why default to `unresolved`?**

Because it makes the **safe state the lazy state**.

Defaulting to `verified` means every mapping anyone adds — in a hurry, from
memory, from a blog post — silently claims to have been checked against
published benchmark text. Nobody has to lie; the default lies for them.

Defaulting to `unresolved` inverts the effort: claiming verification
requires a deliberate act by someone who actually opened the benchmark.

The evidence it works: **all 16** unresolved mappings got there by
omitting `status`, not by anyone marking them unresolved. Under the
opposite default, all 16 would now be claiming verification nobody
performed.

**3. Should an attack path get an ISO control ID?**

**For:** customers organise work by framework. An attack path with no
control is invisible in a compliance dashboard, and reviewers ask "which
control does this map to?"

**Against:** an attack path is a **composite graph observation**, not a
control assessment. ISO 27001 controls describe organisational and
technical measures; "internet → publicly assumable admin role" is a
finding *about a specific topology*. Choosing a control means selecting
from published text and asserting it applies — an act of framework
interpretation.

**Decision: no**, and the codebase reflects it. The reason is the
`unresolved` default's reason: inventing a mapping is worse than lacking
one. If a framework owner later decides attack paths map to a control,
that is their call with published text in hand — and the mechanism already
exists (`FrameworkMapping` with `status`).

Note the paths *are* reachable through compliance today, indirectly: they
enrich `Finding.risk`, and findings carry framework attribution.

**4. All 9 `cis_azure` mappings unverified — risk and remedy?**

**Customer-visible risk:** a customer running Azure sees CIS Azure control
references on their findings and reasonably concludes ComplianceIQ
assesses CIS Azure. If a mapping is wrong, they believe a control is
covered when it is not — and they may present that to an auditor.

The mitigation today is that `status: unresolved` is *recorded*, so the
data supports a caveat. Whether the UI surfaces it is a separate question.
⚠️ **Repository verification required** — no API schema currently exposes
`framework_mappings`.

**To resolve them:** obtain the CIS Microsoft Azure Foundations Benchmark
at a specific version, read each control's text, confirm the rule's
condition actually assesses it (not merely relates to it), and mark
`status: verified` — recording the benchmark version, since control
numbering changes between releases.

That is framework-owner work requiring licensed source material.

**5. Why does `ComplianceScore` exclude INDETERMINATE entirely?**

Because counting them as failures would report a **scanner permission
problem as a customer compliance problem**.

If ComplianceIQ lacks `s3:GetBucketAcl`, every bucket returns
INDETERMINATE. Counted as failures, the customer's storage compliance
drops to 0% — and they would spend a week investigating buckets that may
be perfectly configured.

Counting them as passes is worse: it hides real violations behind a
missing permission.

Excluding them from **both** numerator and denominator means the score
answers *"of the things we could actually assess, what fraction passed?"*
— a true statement. The **`coverage`** companion then answers *"how much
could we assess?"* separately.

Two numbers, two questions, neither contaminating the other. And when
nothing determinate exists, `score` returns `None` rather than 0% or
100%, because there is no honest number.

**6. When is 41 of 68 rules on two controls a problem?**

**Not a problem when** it reflects ISO's genuine structure. `A.8.20`
(network security) and `A.8.24` (cryptography / data protection) really do
cover a large share of cloud misconfiguration, and CSPM findings genuinely
cluster there.

**A problem when** either of these is true:

- **The mapping is under-differentiated** — rules were assigned to the
  nearest broad control rather than the most precise one. Symptom: rules
  in the same control that a reader would not group together.
- **Reporting granularity suffers.** A customer asking "how are we doing
  on A.8.20?" gets one number aggregating 23 unrelated checks. They cannot
  tell whether their weakness is security groups or public IPs.

**How to tell:** read the ISO text for both controls and ask whether each
of the 23 rules genuinely assesses `A.8.20`, or whether some belong to
`A.8.21`, `A.8.22`, or `A.13.x`.

Only the framework owner can answer that, with the standard in hand — it
is exactly the kind of judgement this phase's ownership boundary reserves.
