# AI Service integration — architecture

The client-facing contract lives in
[`docs/integration/ai-service-integration.md`](../integration/ai-service-integration.md).
This document covers the *architectural* decisions behind it.

## Ownership

```
CORE (source of truth)  ──REST──▶  AI SERVICE (reasoning)
      findings                        enrichment
      resources                       correlation
      scans                           remediation proposals
      scores                          financial analysis
```

The AI Service never becomes authoritative for a finding, and never
touches Core's database. Both are load-bearing: a second writer to the
findings tables would make "what did we detect?" unanswerable, and
database access would couple the AI Service to a schema that is
explicitly Core's private implementation detail.

The dashboard must render from Core alone when the AI Service is down.
Nothing in this API depends on the AI Service existing.

## The two-schema decision

The pre-existing `contracts/ai_service` package defines a **frozen
11-field** `FindingContract` whose consumer rejects unknown fields, and
whose status enum has no INDETERMINATE value.

The REST API cannot adopt that shape:

- hiding INDETERMINATE findings reintroduces hidden compliance
- the brief asks for richer fields the contract forbids

Extending the contract would break the AI Service currently being built
against it — a v2 decision, not a Phase 5 one.

So there are two schemas, and neither redefines the other:

| | `FindingResource` | `AiFindingContract` |
|---|---|---|
| Path | `/findings` | `/findings/ai-contract` |
| Fields | 17 | exactly 11 |
| `status` | 3-valued | 2-valued |
| INDETERMINATE | returned | omitted |
| Stability | additive | frozen |

Both are projections of the same domain `Finding`, and the AI projection
goes through the **existing** `finding_to_contract` ACL rather than being
re-derived in the router. That is how "never independently redefine the
same model differently" is honoured: one translation path, two views.

### Why a path, not `?view=ai`

A query parameter that changes the *response schema* makes the OpenAPI
document ambiguous — one operation, two response types — so a generated
client gets one type for two shapes. This was found by a test: FastAPI's
declared `response_model` silently coerced the AI items back to the full
schema.

## Correlation propagation

```
Dashboard ──X-Correlation-ID: abc──▶ Core ──abc──▶ AI Service
```

Core preserves a supplied id, generates one otherwise, returns it on
every response including errors, and stamps it into audit events —
including events written minutes later by a background scan, so an async
pipeline remains traceable to the request that started it.

Inbound ids are sanitized: length-bounded and restricted to printable
non-whitespace ASCII, because an attacker-controlled value lands in every
log line for the request and a newline could forge a log record.

## Local development

`build_stub_app` is the **real** application over in-memory data — real
routing, JWT verification, tenant scoping, error envelope. What
`CIQ_CORE_API_BASE_URL` points at.

It seeds findings across `fail`, `pass` and `indeterminate` so the AI
engineer exercises the indeterminate branch — the one most likely to be
handled wrongly — rather than discovering it in production.

## Invariants

1. Core is the source of truth for findings
2. AI reaches data through REST, never the database
3. JWT `tenant_id` is authoritative
4. Every finding returned belongs to the authenticated tenant
5. `AiFindingContract` stays exactly 11 fields
6. Error `code` values are stable
7. Breaking changes ship as `/api/v2`
8. Correlation IDs propagate
9. **AI-generated remediation is never automatically applied by Core** —
   Core exposes no endpoint that mutates cloud infrastructure, so this
   invariant is structural rather than a policy anyone must remember
