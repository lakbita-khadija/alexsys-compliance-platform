# Finding contract

Two shapes exist, deliberately. Choosing correctly matters.

## `Finding` — the full API shape

Returned by `GET /api/v1/findings` and `/findings/{id}`.

| Field | Owner | Stable | AI | Dashboard | Persisted | Sensitive |
|---|---|---|---|---|---|---|
| `id` | Core | yes | yes | yes | yes | no |
| `tenant_id` | Core (from JWT) | yes | yes | yes | yes | no |
| `resource_id` | Collector | yes | yes | yes | yes | no |
| `rule_id` | Rule catalog | yes | yes | yes | yes | no |
| `framework` | Rule catalog | yes | yes | yes | yes | no |
| `control_id` | Rule catalog | yes | yes | yes | yes | no |
| `domain` | Rule catalog | yes | yes | yes | yes | no |
| `status` | Rule engine | yes | 2-valued only | yes | yes | no |
| `severity` | Rule catalog | yes | yes | yes | yes | no |
| `evidence` | Rule engine | yes | yes | yes | yes | **redacted** |
| `detected_at` | Rule engine | yes | yes | yes | yes | no |
| `region` | Collector | yes | no | yes | yes | no |
| `account_id` | Collector | yes | no | yes | yes | no |
| `scan_key` | Scan | yes | no | yes | yes | no |
| `logical_finding_id` | Core | yes | no | yes | yes | no |
| `risk` / `confidence` | Core | yes | no | yes | yes | no |

`evidence` passes through redaction before storage, so secret-shaped keys
are already `[REDACTED]` by the time they are returned.

## `AiFindingContract` — the frozen 11 fields

Exactly `id`, `tenant_id`, `resource_id`, `rule_id`, `framework`,
`control_id`, `domain`, `status`, `severity`, `evidence`, `detected_at`.

Served at `/findings/ai-contract` and `/findings/{id}/ai-contract`, and
produced by the existing `contracts/ai_service` ACL — never re-derived,
so the two cannot drift.

**Will not gain fields.** The AI Service rejects unknown ones.

## `status` is three-valued in the API

`fail` · `pass` · `indeterminate`

**`indeterminate` is not a pass.** It means the check could not be
evaluated from the data collected. Treating it as compliant reintroduces
hidden compliance — a clean dashboard over an unverified control — which
is precisely what the three-valued rule engine exists to prevent.

The AI contract's status has only two values, so INDETERMINATE findings
are **omitted** from that view rather than coerced. Coercing would invent
a verdict.

## Identity: `id` vs `logical_finding_id`

- `id` — **physical**, unique to one finding in one scan, changes every scan
- `logical_finding_id` — **logical**, stable across scans for the same issue

Key enrichment, deduplication and history on `logical_finding_id`. Keying
on `id` means re-enriching everything after every scan.

Treat it as **opaque**: it contains `:`, and so do ARNs and Azure
resource ids, so splitting it does not reliably recover its parts. The
components are available as separate fields.

## Filters

`framework`, `severity`, `status`, `lifecycle_state`, `domain`,
`provider`, `resource_id`, `rule_id`, `scan_key`, `account_id`,
`detected_after`, `detected_before`, plus `sort`, `limit`, `offset`.

Enum values are closed; unknown ones are 422.

**There is no `tenant_id` filter.** It is the security boundary, not a
predicate.
