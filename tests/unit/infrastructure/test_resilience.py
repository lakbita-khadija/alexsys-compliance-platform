"""Tests for the cloud resilience layer (audit G1, G2).

Every test injects `sleep` and `monotonic`, so the suite exercises real
backoff arithmetic in microseconds. A retry test that actually sleeps is
a test nobody runs, and an untested retry layer is worse than none — it
creates confidence without behaviour.
"""

from __future__ import annotations

import random

import pytest

from infrastructure.cloud.resilience import (
    CollectionStats,
    RetryBudgetExhausted,
    RetryPolicy,
    call_with_retry,
    collect_each,
    compute_backoff,
    error_code_of,
    is_permission_denied,
    is_retryable,
    is_throttle,
    paginate,
    retry_after_hint,
)


class FakeClientError(Exception):
    """Mimics botocore's ClientError shape."""

    def __init__(self, code: str, *, headers: dict | None = None) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPHeaders": headers or {}},
        }


class FakeAzureError(Exception):
    """Mimics an azure-core error shape."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.error_code = code


class Recorder:
    """Captures sleeps and advances a fake clock by the slept amount."""

    def __init__(self) -> None:
        self.sleeps: list[float] = []
        self.now = 0.0

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


class TestErrorClassification:
    @pytest.mark.parametrize(
        "code", ["Throttling", "RequestLimitExceeded", "TooManyRequestsException", "SlowDown"]
    )
    def test_throttles_are_retryable(self, code) -> None:
        exc = FakeClientError(code)
        assert is_throttle(exc)
        assert is_retryable(exc)

    @pytest.mark.parametrize("code", ["InternalError", "ServiceUnavailable", "503"])
    def test_transient_failures_are_retryable(self, code) -> None:
        assert is_retryable(FakeClientError(code))

    @pytest.mark.parametrize(
        "code", ["AccessDenied", "UnauthorizedOperation", "ValidationException", "NoSuchBucket"]
    )
    def test_terminal_errors_are_not_retryable(self, code) -> None:
        # Retrying these wastes the budget a real throttle needs and
        # turns a fast, clear error into a slow one.
        assert not is_retryable(FakeClientError(code))

    def test_an_unrecognized_error_is_treated_as_terminal(self) -> None:
        # Conservative by design: retrying an unknown error mostly
        # converts a fast failure into a hung scan.
        assert not is_retryable(FakeClientError("SomeBrandNewErrorCode"))

    def test_permission_denied_is_detected_across_providers(self) -> None:
        assert is_permission_denied(FakeClientError("AccessDenied"))
        assert is_permission_denied(FakeAzureError("AuthorizationFailed"))

    def test_error_code_reads_azure_shape(self) -> None:
        assert error_code_of(FakeAzureError("TooManyRequests")) == "TooManyRequests"

    def test_error_code_falls_back_to_class_name(self) -> None:
        assert error_code_of(ValueError("boom")) == "ValueError"


class TestRetryAfterHint:
    def test_http_retry_after_is_honoured(self) -> None:
        assert retry_after_hint(FakeClientError("Throttling", headers={"Retry-After": "7"})) == 7.0

    def test_azure_ratelimit_header_is_honoured(self) -> None:
        exc = FakeClientError("429", headers={"x-ms-ratelimit-reset-after": "3.5"})
        assert retry_after_hint(exc) == 3.5

    def test_header_lookup_is_case_insensitive(self) -> None:
        assert retry_after_hint(FakeClientError("Throttling", headers={"retry-after": "2"})) == 2.0

    def test_absent_header_returns_none(self) -> None:
        assert retry_after_hint(FakeClientError("Throttling")) is None

    def test_an_http_date_is_ignored_rather_than_crashing(self) -> None:
        # Retry-After may be a date. We fall back to computed backoff
        # instead of raising — the function must be total.
        exc = FakeClientError("Throttling", headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        assert retry_after_hint(exc) is None


class TestBackoff:
    def test_backoff_grows_exponentially_before_jitter(self) -> None:
        policy = RetryPolicy(base_delay=1.0, max_delay=100.0)
        rng = random.Random(0)
        # Full jitter samples uniformly from [0, ceiling], so assert on
        # the ceiling rather than the sample.
        for attempt, ceiling in [(0, 1.0), (1, 2.0), (2, 4.0), (3, 8.0)]:
            samples = [compute_backoff(attempt, policy, rng=rng) for _ in range(50)]
            assert max(samples) <= ceiling
            assert min(samples) >= 0.0

    def test_backoff_is_capped(self) -> None:
        policy = RetryPolicy(base_delay=1.0, max_delay=5.0)
        assert compute_backoff(20, policy, rng=random.Random(1)) <= 5.0

    def test_jitter_actually_varies(self) -> None:
        # Without jitter every collector retries at the same instant and
        # re-triggers the throttle that caused the retry.
        policy = RetryPolicy(base_delay=10.0, max_delay=100.0)
        rng = random.Random(7)
        samples = {compute_backoff(3, policy, rng=rng) for _ in range(20)}
        assert len(samples) > 1


class TestCallWithRetry:
    def test_a_successful_call_is_not_retried(self) -> None:
        stats = CollectionStats()
        result = call_with_retry(lambda: "ok", stats=stats)
        assert result == "ok"
        assert stats.api_calls == 1
        assert stats.retries == 0

    def test_a_throttle_is_retried_then_succeeds(self) -> None:
        rec = Recorder()
        stats = CollectionStats()
        calls = {"n": 0}

        def flaky() -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise FakeClientError("Throttling")
            return "ok"

        result = call_with_retry(
            flaky, stats=stats, sleep=rec.sleep, monotonic=rec.monotonic
        )
        assert result == "ok"
        assert calls["n"] == 3
        assert stats.retries == 2
        assert stats.throttled == 2
        assert len(rec.sleeps) == 2

    def test_access_denied_raises_immediately_and_is_not_retried(self) -> None:
        rec = Recorder()
        stats = CollectionStats()

        def denied() -> None:
            raise FakeClientError("AccessDenied")

        with pytest.raises(FakeClientError):
            call_with_retry(denied, stats=stats, sleep=rec.sleep, monotonic=rec.monotonic)

        assert stats.api_calls == 1
        assert stats.retries == 0
        assert rec.sleeps == [], "a terminal error must not sleep"
        assert stats.permission_denied == 1

    def test_the_original_exception_is_raised_for_terminal_errors(self) -> None:
        # Callers classify on the provider error; wrapping it would
        # destroy that.
        with pytest.raises(FakeClientError) as caught:
            call_with_retry(lambda: (_ for _ in ()).throw(FakeClientError("NoSuchBucket")))
        assert error_code_of(caught.value) == "NoSuchBucket"

    def test_exhausting_attempts_raises_budget_exhausted(self) -> None:
        rec = Recorder()
        stats = CollectionStats()

        with pytest.raises(RetryBudgetExhausted):
            call_with_retry(
                lambda: (_ for _ in ()).throw(FakeClientError("Throttling")),
                policy=RetryPolicy(max_attempts=3, base_delay=0.01),
                stats=stats,
                sleep=rec.sleep,
                monotonic=rec.monotonic,
            )

        assert stats.api_calls == 3
        assert len(rec.sleeps) == 2, "no sleep after the final attempt"

    def test_the_underlying_error_is_preserved_as_cause(self) -> None:
        rec = Recorder()
        with pytest.raises(RetryBudgetExhausted) as caught:
            call_with_retry(
                lambda: (_ for _ in ()).throw(FakeClientError("Throttling")),
                policy=RetryPolicy(max_attempts=2, base_delay=0.01),
                sleep=rec.sleep,
                monotonic=rec.monotonic,
            )
        assert isinstance(caught.value.__cause__, FakeClientError)

    def test_the_time_budget_stops_retrying(self) -> None:
        # A persistently throttled endpoint must not hang a scan.
        rec = Recorder()
        stats = CollectionStats()

        with pytest.raises(RetryBudgetExhausted):
            call_with_retry(
                lambda: (_ for _ in ()).throw(FakeClientError("Throttling")),
                policy=RetryPolicy(
                    max_attempts=50, base_delay=1.0, max_delay=5.0, max_elapsed=6.0
                ),
                stats=stats,
                sleep=rec.sleep,
                monotonic=rec.monotonic,
            )

        assert rec.now <= 6.0
        assert stats.api_calls < 50, "stopped on the time budget, not the attempt budget"

    def test_a_server_hint_overrides_computed_backoff(self) -> None:
        rec = Recorder()
        calls = {"n": 0}

        def flaky() -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise FakeClientError("Throttling", headers={"Retry-After": "4"})
            return "ok"

        call_with_retry(
            flaky,
            policy=RetryPolicy(base_delay=0.01, max_delay=30.0),
            sleep=rec.sleep,
            monotonic=rec.monotonic,
        )
        assert rec.sleeps == [4.0], "the service knows its own capacity"


class TestPaginate:
    def test_all_pages_are_yielded(self) -> None:
        pages = list(paginate(iter([{"n": 1}, {"n": 2}, {"n": 3}])))
        assert [p["n"] for p in pages] == [1, 2, 3]

    def test_a_throttle_mid_pagination_is_survived(self) -> None:
        rec = Recorder()
        state = {"i": 0, "raised": False}
        source = [{"n": 1}, {"n": 2}, {"n": 3}]

        class Flaky:
            def __iter__(self):
                return self

            def __next__(self):
                if state["i"] == 2 and not state["raised"]:
                    state["raised"] = True
                    raise FakeClientError("Throttling")
                if state["i"] >= len(source):
                    raise StopIteration
                page = source[state["i"]]
                state["i"] += 1
                return page

        pages = list(paginate(Flaky(), sleep=rec.sleep))
        assert [p["n"] for p in pages] == [1, 2, 3], "no page lost to a throttle"

    def test_a_dead_generator_raises_instead_of_returning_a_short_list(self) -> None:
        """Regression: the bug this function was written to prevent.

        A generator that raises is finalized (PEP 342), so a retried
        `next()` gets StopIteration rather than the next page. The first
        version of `paginate` read that as "end of pages" and returned
        the pages collected so far — silently truncating, which is
        exactly the failure it exists to stop.

        boto3's paginators are generators, so this is the real-world
        shape, not a contrived one. Caught by a collector test, not by
        review.
        """

        rec = Recorder()

        def one_page_then_throttle():
            yield {"n": 1}
            raise FakeClientError("Throttling")

        with pytest.raises(RetryBudgetExhausted, match="cannot resume"):
            list(
                paginate(
                    one_page_then_throttle(),
                    policy=RetryPolicy(max_attempts=2, base_delay=0.01),
                    sleep=rec.sleep,
                )
            )

    def test_a_clean_generator_still_terminates_normally(self) -> None:
        # The guard must not turn a normal end-of-iteration into an error.
        def two_pages():
            yield {"n": 1}
            yield {"n": 2}

        assert [p["n"] for p in paginate(two_pages())] == [1, 2]

    def test_exhausted_retries_raise_rather_than_truncating(self) -> None:
        # Silent truncation is this system's worst failure mode: it
        # reports compliance for resources it never examined.
        rec = Recorder()

        class AlwaysThrottled:
            def __iter__(self):
                return self

            def __next__(self):
                raise FakeClientError("Throttling")

        with pytest.raises(RetryBudgetExhausted):
            list(
                paginate(
                    AlwaysThrottled(),
                    policy=RetryPolicy(max_attempts=2, base_delay=0.01),
                    sleep=rec.sleep,
                )
            )


class TestCollectEach:
    def test_one_failure_does_not_lose_the_others(self) -> None:
        # The §3 requirement: 10,000 resources, one AccessDenied, 9,999
        # still collected.
        stats = CollectionStats()

        def handler(n: int) -> int:
            if n == 3:
                raise FakeClientError("AccessDenied")
            return n * 10

        results = collect_each(range(6), handler, stats=stats)
        assert results == [0, 10, 20, 40, 50]
        assert stats.skipped_resources == 1
        assert stats.permission_denied == 1

    def test_a_skipped_resource_marks_the_run_degraded(self) -> None:
        # Losing a resource silently would let a scan claim coverage it
        # does not have. `degraded` is what makes the caller report
        # PARTIAL instead of COMPLETED.
        stats = CollectionStats()
        collect_each(
            [1], lambda n: (_ for _ in ()).throw(FakeClientError("AccessDenied")), stats=stats
        )
        assert stats.degraded is True

    def test_a_clean_run_is_not_degraded(self) -> None:
        stats = CollectionStats()
        collect_each([1, 2], lambda n: n, stats=stats)
        assert stats.degraded is False

    def test_none_results_are_dropped(self) -> None:
        assert collect_each([1, 2, 3], lambda n: n if n % 2 else None) == [1, 3]

    def test_error_codes_are_tallied(self) -> None:
        stats = CollectionStats()
        collect_each(
            range(3),
            lambda n: (_ for _ in ()).throw(FakeClientError("AccessDenied")),
            stats=stats,
        )
        assert stats.errors_by_code["AccessDenied"] == 3


class TestStats:
    def test_merge_accumulates(self) -> None:
        a = CollectionStats(api_calls=3, retries=1)
        a.record_error("Throttling")
        b = CollectionStats(api_calls=2, skipped_resources=1)
        b.record_error("Throttling")
        a.merge(b)
        assert a.api_calls == 5
        assert a.skipped_resources == 1
        assert a.errors_by_code["Throttling"] == 2
