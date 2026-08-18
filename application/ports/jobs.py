"""The scan job port (Phase 5, §26).

``POST /api/v1/scans`` must return ``202 Accepted`` immediately with a
scan id, not block for however long it takes to enumerate a cloud
account. A real scan makes hundreds of throttled API calls; a
synchronous endpoint would hold an HTTP connection open for minutes and
time out behind any load balancer.

So submission and execution are separated by this port. What sits behind
it is a deployment decision, not an architectural one:

* **in-process** (what Phase 5 ships) — a background worker thread.
  Correct, dependency-free, and adequate for a single-instance
  deployment. Its honest limitation is that a process restart loses
  running jobs; because scan state is persisted at each transition, such
  a scan is recoverable as RUNNING-but-stale rather than lost silently.
* **a real queue** (Celery / RQ / arq / SQS) — swappable later by
  implementing this same interface. No use case changes.

The port deliberately exposes only *submission*. Cancellation, retry and
priority are real requirements that Phase 5 has no concrete need for
yet, and inventing their semantics now would mean guessing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

#: A submitted unit of work. Takes no arguments and returns nothing:
#: everything it needs is captured at submission, and its result is
#: communicated by persisting scan state, never by a return value the
#: HTTP caller has already stopped waiting for.
ScanJob = Callable[[], None]


class ScanJobRunner(ABC):
    """Port: execute a scan outside the request/response cycle."""

    @abstractmethod
    def submit(self, job: ScanJob, *, job_name: str) -> None:
        """Accept a job for execution and return immediately.

        Returning normally means the job was ACCEPTED, not that it
        succeeded — the caller has already sent ``202`` by the time it
        runs. Implementations must therefore never let an exception from
        ``job`` escape into the request thread, and must record the
        failure where a later ``GET /scans/{id}`` can report it.

        ``job_name`` is for logging and thread naming only; it carries no
        semantics and must never contain tenant data or secrets.
        """
