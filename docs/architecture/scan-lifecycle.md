# Scan lifecycle

## States

```
              ┌──────────┐
              │  QUEUED  │  persisted by POST /scans, before the job runs
              └────┬─────┘
                   │ worker starts
              ┌────▼─────┐
              │ RUNNING  │  collecting → normalizing → evaluating → scoring
              └────┬─────┘
     ┌─────────────┼─────────────┬──────────────┐
     ▼             ▼             ▼              ▼
┌─────────┐  ┌─────────┐  ┌─────────┐   ┌───────────┐
│COMPLETED│  │ PARTIAL │  │ FAILED  │   │ CANCELLED │
└─────────┘  └─────────┘  └─────────┘   └───────────┘
                    all terminal
```

Transitions are enforced by the `Scan` aggregate (`_ALLOWED_TRANSITIONS`)
and mirrored by CHECK constraints, so a terminal scan cannot be
re-completed by any write path.

## Why `collecting`/`normalizing`/`evaluating`/`scoring` are not states

They are **phases within RUNNING**, not peers of it. Promoting them to
top-level states would break the Phase 4 state machine and its
constraints for no gain — a client polling for completion cares whether
the scan is terminal, not which internal stage it reached. Progress
reporting, if needed, belongs in an additive `phase` field.

## Why `PARTIAL` exists

A scan that enumerated S3 but was denied KMS has **not** verified KMS.
Reporting it as COMPLETED tells an auditor that KMS was checked and found
compliant — which is false, and is the kind of false assurance a
compliance product must never produce.

`Scan.complete()` raises if any errors are present; the caller must use
`complete_partially()`. The database mirrors it.

## Ordering guarantee at submission

```
1. derive scan_key, persist as QUEUED   (own transaction, committed)
2. submit the job
3. return 202
```

Persisting first means a scan can never run without a record of it
existing. The reverse order has a window where the job starts, calls real
cloud APIs, and nothing in the database knows — a crash then leaves no
trace of a scan that touched production infrastructure.

## Worker guarantees

`ScanWorker` catches every exception. Whatever fails, the scan is marked
terminal:

- success → `PersistScanResult` (atomic) → `ComputeScoresForScan` → audit
- failure → status FAILED → audit with the exception **type** only

The exception message is deliberately not recorded: a provider error
string can quote a request containing sensitive parameters.

A worker that raised and left a scan RUNNING forever would be worse than
one that failed loudly — the API would report "in progress" indefinitely
and nobody would know to retry.

## Idempotency

Scan keys are deterministic: same target, same instant, same key. A
duplicate submission while one is running is a **409**. A re-persisted
scan collides with itself and `ON CONFLICT DO UPDATE` makes it a no-op.

## Job execution

Behind `ScanJobRunner`:

- `ThreadScanJobRunner` — background threads. Adequate for a single
  instance, dependency-free. A process restart loses running jobs; because
  state is persisted at each transition, such a scan is visible as
  RUNNING-but-stale rather than vanishing. **No reaper ships in Phase 5.**
- `InlineScanJobRunner` — runs immediately, for tests and the stub. Named
  so its unsuitability for production is obvious at the wiring site.
- A real queue (Celery/RQ/arq/SQS) implements the same interface. No use
  case changes.
