"""Cloud API resilience: retry, backoff, throttling, pagination.

Audit gap G1 — the highest-severity finding, and provider-neutral on
purpose so AWS and Azure share one tested implementation instead of two
divergent ones.

## Why this exists

Scanning a real account makes thousands of API calls. Both AWS and Azure
throttle aggressively, and both return transient 5xx under load. Before
this module there was no retry anywhere in ``infrastructure/cloud/``, so
a single ``Throttling`` response propagated up and the per-service
isolation in ``AwsCollector`` dropped the **entire service** from the
scan. One transient 429 cost a customer all of their S3 coverage.

Reported honestly as a PARTIAL scan — but a CSPM that loses a whole
service to one rate-limit response is not usable at enterprise scale.

## Design decisions

**Only retry what is actually retryable.** ``AccessDenied`` will fail
identically on every attempt; retrying it wastes the budget that a real
throttle needs, and turns a fast, clear permission error into a slow one.
Classification is explicit and errs toward *not* retrying — an unknown
error is treated as terminal.

**Full jitter, not fixed backoff.** Every collector starts at the same
instant, so synchronized retries produce a thundering herd that
re-triggers the throttle that caused them. ``sleep = random(0, min(cap,
base * 2**attempt))`` (the AWS Architecture Blog's "Full Jitter") spreads
them out. Randomness lives here and nowhere else, and the sleep function
is injectable so tests are deterministic and instant.

**Respect server-provided retry hints.** ``Retry-After`` and
``x-ms-ratelimit-reset-after`` exist because the service knows better
than our formula. When present they win over the computed backoff.

**Budgeted, not unbounded.** Retrying forever converts a broken
dependency into a hung scan. Attempts and total elapsed time are both
capped.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, TypeVar

logger = logging.getLogger("complianceiq.cloud.resilience")

T = TypeVar("T")

#: Error codes/classes that indicate rate limiting. Retrying these is the
#: entire point of the module.
THROTTLE_CODES = frozenset(
    {
        # AWS
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottled",
        "RequestThrottledException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "SlowDown",
        "EC2ThrottledException",
        "LimitExceededException",
        # Azure / generic HTTP
        "TooManyRequests",
        "429",
    }
)

#: Transient server-side failures. Distinct from throttling because they
#: warrant a different log level — a 500 is the provider misbehaving,
#: a 429 is us asking too fast.
TRANSIENT_CODES = frozenset(
    {
        "InternalError",
        "InternalFailure",
        "InternalServerError",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "RequestTimeout",
        "RequestTimeoutException",
        "GatewayTimeout",
        "500",
        "502",
        "503",
        "504",
    }
)

#: Never retried. Every one of these fails identically on every attempt,
#: so a retry only delays an error the operator needs to see.
TERMINAL_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthFailure",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidParameterValue",
        "InvalidParameterCombination",
        "ValidationException",
        "ValidationError",
        "MalformedPolicyDocument",
        "NoSuchEntity",
        "NoSuchBucket",
        "ResourceNotFoundException",
        "AuthorizationFailed",
        "Forbidden",
        "401",
        "403",
        "404",
    }
)


class RetryBudgetExhausted(Exception):
    """Every retry attempt was used and the call still failed.

    Carries the last underlying exception as ``__cause__`` so the caller
    sees the real provider error, not just "we gave up".
    """


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How hard to try, and how long to wait between attempts.

    Defaults are tuned for a bulk scanner rather than an interactive
    client: a scan can afford ~30s of backoff on one call if it means not
    losing an entire service's coverage.
    """

    max_attempts: int = 5
    #: First backoff, in seconds. Doubles per attempt before jitter.
    base_delay: float = 0.5
    #: Ceiling on a single sleep. Without it, attempt 8 would sleep for
    #: minutes.
    max_delay: float = 20.0
    #: Ceiling on total time spent retrying ONE call, across all attempts.
    #: Prevents a persistently throttled endpoint from hanging a scan.
    max_elapsed: float = 60.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay <= 0 or self.max_delay <= 0:
            raise ValueError("delays must be positive")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must not be smaller than base_delay")


@dataclass
class CollectionStats:
    """What a collection run actually did (§3).

    Returned rather than logged so the caller chooses its own
    observability stack, and so tests can assert on it. Also the only way
    to prove coverage: "0 findings" is meaningless without knowing
    whether 0 or 5,000 resources were examined.
    """

    api_calls: int = 0
    retries: int = 0
    throttled: int = 0
    transient_errors: int = 0
    permission_denied: int = 0
    #: Items skipped because ONE resource failed while others succeeded.
    #: Non-zero means the scan is incomplete and the caller should mark
    #: it PARTIAL rather than COMPLETED.
    skipped_resources: int = 0
    seconds_sleeping: float = 0.0
    errors_by_code: dict[str, int] = field(default_factory=dict)

    def record_error(self, code: str) -> None:
        self.errors_by_code[code] = self.errors_by_code.get(code, 0) + 1

    @property
    def degraded(self) -> bool:
        """Whether this run lost data it should have collected."""

        return self.skipped_resources > 0 or self.permission_denied > 0

    def merge(self, other: "CollectionStats") -> None:
        self.api_calls += other.api_calls
        self.retries += other.retries
        self.throttled += other.throttled
        self.transient_errors += other.transient_errors
        self.permission_denied += other.permission_denied
        self.skipped_resources += other.skipped_resources
        self.seconds_sleeping += other.seconds_sleeping
        for code, count in other.errors_by_code.items():
            self.errors_by_code[code] = self.errors_by_code.get(code, 0) + count


def error_code_of(exc: BaseException) -> str:
    """Best-effort provider-neutral error code.

    Reads botocore's ``response["Error"]["Code"]``, Azure's ``error_code``
    / ``status_code``, then falls back to the exception class name. The
    fallback matters: an unrecognized error must still produce a stable
    string for statistics, and it must classify as terminal rather than
    being retried blindly.
    """

    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return str(code)
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if status:
            return str(status)

    for attribute in ("error_code", "code", "status_code"):
        value = getattr(exc, attribute, None)
        if value is not None and not callable(value):
            return str(value)

    return type(exc).__name__


def is_throttle(exc: BaseException) -> bool:
    return error_code_of(exc) in THROTTLE_CODES


def is_transient(exc: BaseException) -> bool:
    return error_code_of(exc) in TRANSIENT_CODES


def is_permission_denied(exc: BaseException) -> bool:
    code = error_code_of(exc)
    return code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationFailed",
        "Forbidden",
        "401",
        "403",
    }


def is_retryable(exc: BaseException) -> bool:
    """Whether retrying could plausibly succeed.

    Deliberately conservative: only codes we recognize as throttling or
    transient are retried. Anything unrecognized is terminal, because
    retrying an unknown error mostly turns a fast failure into a slow
    one, and a scan that hangs is worse than a scan that reports an
    error.
    """

    code = error_code_of(exc)
    if code in TERMINAL_CODES:
        return False
    return code in THROTTLE_CODES or code in TRANSIENT_CODES


def retry_after_hint(exc: BaseException) -> float | None:
    """Seconds the SERVER asked us to wait, if it said.

    The service knows its own capacity better than our backoff formula,
    so an explicit hint always wins. Recognizes HTTP ``Retry-After`` and
    Azure's ``x-ms-ratelimit-reset-after``.
    """

    headers: Any = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        headers = response.get("ResponseMetadata", {}).get("HTTPHeaders")
    elif response is not None:
        headers = getattr(response, "headers", None)
    if headers is None:
        headers = getattr(exc, "headers", None)
    if not headers:
        return None

    try:
        lookup = {str(k).lower(): v for k, v in dict(headers).items()}
    except Exception:  # noqa: BLE001 - malformed headers are not fatal
        return None

    for name in ("retry-after", "x-ms-ratelimit-reset-after"):
        raw = lookup.get(name)
        if raw is None:
            continue
        try:
            seconds = float(raw)
        except (TypeError, ValueError):
            # Retry-After may be an HTTP date. Parsing it is possible but
            # rarely used by these APIs; falling back to computed backoff
            # is safe and keeps this function total.
            continue
        if seconds >= 0:
            return seconds
    return None


def compute_backoff(
    attempt: int,
    policy: RetryPolicy,
    *,
    rng: random.Random | None = None,
) -> float:
    """Full-jitter exponential backoff for a zero-based attempt number.

    ``random(0, min(cap, base * 2**attempt))``. The jitter is not
    decoration: every collector starts simultaneously, so without it all
    retries land at the same moment and re-trigger the throttle that
    caused them.
    """

    ceiling = min(policy.max_delay, policy.base_delay * (2**attempt))
    generator = rng or random
    return generator.uniform(0.0, ceiling)


def call_with_retry(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    stats: CollectionStats | None = None,
    description: str = "cloud API call",
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    rng: random.Random | None = None,
) -> T:
    """Invoke ``operation``, retrying throttles and transient failures.

    ``sleep``, ``monotonic`` and ``rng`` are injectable so tests run
    instantly and deterministically — a retry test that actually sleeps
    is a test nobody runs.

    Raises the original exception for terminal errors (so callers can
    classify permission problems), and ``RetryBudgetExhausted`` when
    retryable errors used the whole budget.
    """

    policy = policy or RetryPolicy()
    stats = stats if stats is not None else CollectionStats()
    started = monotonic()
    last_error: BaseException | None = None

    for attempt in range(policy.max_attempts):
        try:
            stats.api_calls += 1
            return operation()
        except Exception as exc:  # noqa: BLE001 - classified immediately below
            last_error = exc
            code = error_code_of(exc)
            stats.record_error(code)

            if is_permission_denied(exc):
                stats.permission_denied += 1

            if not is_retryable(exc):
                # Terminal. Raise the ORIGINAL exception so the caller
                # can distinguish AccessDenied from a real fault.
                raise

            if is_throttle(exc):
                stats.throttled += 1
            else:
                stats.transient_errors += 1

            if attempt == policy.max_attempts - 1:
                break

            delay = retry_after_hint(exc)
            if delay is None:
                delay = compute_backoff(attempt, policy, rng=rng)
            delay = min(delay, policy.max_delay)

            elapsed = monotonic() - started
            if elapsed + delay > policy.max_elapsed:
                # Sleeping would blow the per-call budget. Stop now
                # rather than hanging the scan on a persistently
                # unavailable endpoint.
                logger.warning(
                    "retry budget (time) exhausted for %s after %.1fs (%s)",
                    description,
                    elapsed,
                    code,
                )
                break

            stats.retries += 1
            stats.seconds_sleeping += delay
            logger.info(
                "retrying %s after %s (attempt %d/%d, sleeping %.2fs)",
                description,
                code,
                attempt + 1,
                policy.max_attempts,
                delay,
            )
            sleep(delay)

    raise RetryBudgetExhausted(
        f"{description} failed after {policy.max_attempts} attempts "
        f"({error_code_of(last_error) if last_error else 'unknown'})"
    ) from last_error


def paginate(
    page_source: Iterable[Any],
    *,
    policy: RetryPolicy | None = None,
    stats: CollectionStats | None = None,
    description: str = "pagination",
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[Any]:
    """Iterate pages, retrying a throttle **mid-pagination**.

    Audit gap G2. A paginator that dies on page 40 of 60 is worse than
    one that fails immediately: it returns a partial result that looks
    complete, and a CSPM then reports compliance for resources it never
    saw. Silent truncation is this system's worst failure mode.

    Retrying is applied to advancing the iterator, so a throttle between
    pages is survived rather than truncating the result.
    """

    policy = policy or RetryPolicy()
    stats = stats if stats is not None else CollectionStats()
    iterator = iter(page_source)

    while True:
        # Tracks whether a retryable error was seen while producing THIS
        # page. It is the difference between two outcomes that look
        # identical from the outside and could not be more different.
        saw_error = False

        def advance() -> Any:
            nonlocal saw_error
            try:
                return next(iterator)
            except StopIteration:
                raise
            except Exception:
                saw_error = True
                raise

        try:
            page = call_with_retry(
                advance,
                policy=policy,
                stats=stats,
                description=description,
                sleep=sleep,
            )
        except StopIteration:
            # A generator that raised is FINALIZED — PEP 342. Python's
            # own paginators (boto3's included) are generators, so once
            # a throttle escapes, every later next() raises StopIteration
            # rather than resuming.
            #
            # Treating that as "end of pages" is how a throttle silently
            # truncates a result set, which is this system's worst
            # failure mode: it reports compliance for resources it never
            # examined. So a StopIteration that follows an error is a
            # DEAD ITERATOR, not a complete one, and it must raise.
            #
            # (Found by a test, not by review: the first version of this
            # function returned the short list.)
            if saw_error:
                raise RetryBudgetExhausted(
                    f"{description} was interrupted and its paginator cannot resume — "
                    "results would be silently truncated"
                ) from None
            return
        except RetryBudgetExhausted:
            # Deliberately NOT swallowed, for the same reason.
            raise
        yield page


def collect_each(
    items: Iterable[T],
    handler: Callable[[T], Any],
    *,
    stats: CollectionStats | None = None,
    describe: Callable[[T], str] = repr,
) -> list[Any]:
    """Apply ``handler`` to every item, isolating per-item failure (§3).

    The rule from the brief: an account with 10,000 resources where one
    returns ``AccessDenied`` must still yield the other 9,999.

    Failures are counted in ``stats.skipped_resources``, which makes the
    run ``degraded`` — so the caller can mark the scan PARTIAL instead of
    COMPLETED. Losing one resource silently would let a scan claim
    coverage it does not have.

    The item description is passed through ``describe`` and logged; the
    exception message is deliberately NOT logged at info level, because a
    provider error string can quote request parameters.
    """

    stats = stats if stats is not None else CollectionStats()
    results: list[Any] = []

    for item in items:
        try:
            outcome = handler(item)
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            stats.skipped_resources += 1
            code = error_code_of(exc)
            stats.record_error(code)
            if is_permission_denied(exc):
                stats.permission_denied += 1
            logger.warning(
                "skipping resource after %s: %s", code, describe(item)
            )
            continue
        if outcome is not None:
            results.append(outcome)

    return results
