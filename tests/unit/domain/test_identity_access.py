"""STEP 2 — identity → resource access derivation.

The failure this module exists to prevent is not a missing edge; it is
**500 edges**. A role with `s3:*` on `Resource: "*"` reaches every bucket
in the account, and turning that into one edge per bucket explodes the
graph and destroys the signal simultaneously — once a role reaches
everything, "this role reaches the sensitive bucket" distinguishes
nothing.

So the tests that matter most here assert that a wildcard produces
**nothing**.
"""

from __future__ import annotations

import pytest

from domain.graph.identity_access import (
    AccessEvidence,
    AccessGrant,
    classify_pattern,
    derive_access_edges,
    grants_from_mappings,
    has_unconstrained_access,
    pattern_matches,
)
from domain.shared.identifiers import ResourceId

BUCKETS = [ResourceId("acme-reports"), ResourceId("acme-logs"), ResourceId("other-data")]


def allow(resources, actions=("s3:GetObject",), **kw):
    return AccessGrant(effect="Allow", actions=tuple(actions), resources=tuple(resources), **kw)


def deny(resources, actions=("s3:GetObject",), **kw):
    return AccessGrant(effect="Deny", actions=tuple(actions), resources=tuple(resources), **kw)


def targets(derived):
    return [str(d.target) for d in derived]


class TestPatternClassification:
    @pytest.mark.parametrize(
        "pattern,expected",
        [
            ("arn:aws:s3:::acme-reports", AccessEvidence.EXACT),
            ("acme-reports", AccessEvidence.EXACT),
            ("arn:aws:s3:::acme-*", AccessEvidence.BROAD),
            ("arn:aws:s3:::acme-reports/*", AccessEvidence.BROAD),
            # The two that must never become edges.
            ("*", AccessEvidence.POTENTIAL),
            ("arn:aws:s3:::*", AccessEvidence.POTENTIAL),
            ("", AccessEvidence.POTENTIAL),
        ],
    )
    def test_classification(self, pattern, expected) -> None:
        assert classify_pattern(pattern) == expected

    def test_service_wide_wildcard_is_not_broad(self) -> None:
        # `arn:aws:s3:::*` LOOKS constrained — it names a service — but it
        # selects every bucket, so it is indistinguishable from `*`.
        assert classify_pattern("arn:aws:s3:::*") == AccessEvidence.POTENTIAL


class TestWildcardDoesNotExplodeTheGraph:
    """The single most important behaviour in this module."""

    def test_full_wildcard_produces_no_edges(self) -> None:
        assert derive_access_edges([allow(["*"])], BUCKETS) == ()

    def test_service_wide_wildcard_produces_no_edges(self) -> None:
        assert derive_access_edges([allow(["arn:aws:s3:::*"])], BUCKETS) == ()

    def test_not_resource_produces_no_edges(self) -> None:
        # "Everything except these" — we do not enumerate a complement.
        grant = allow(["arn:aws:s3:::secret"], inverted_resources=True)
        assert derive_access_edges([grant], BUCKETS) == ()

    def test_unconstrained_access_is_recorded_instead(self) -> None:
        # The fact is not lost — it becomes a property of the IDENTITY,
        # which is what it actually is: one fact about one resource, not
        # N relationships.
        assert has_unconstrained_access([allow(["*"])]) is True
        assert has_unconstrained_access([allow(["arn:aws:s3:::acme-reports"])]) is False


class TestExactAndBroadMatching:
    def test_exact_arn_matches_the_named_bucket_only(self) -> None:
        derived = derive_access_edges([allow(["arn:aws:s3:::acme-reports"])], BUCKETS)
        assert targets(derived) == ["acme-reports"]
        assert derived[0].evidence == AccessEvidence.EXACT
        assert derived[0].confidence == "high"

    def test_broad_prefix_matches_only_the_prefixed_bucket(self) -> None:
        derived = derive_access_edges([allow(["arn:aws:s3:::acme-*"])], BUCKETS)
        assert targets(derived) == ["acme-logs", "acme-reports"]
        assert all(d.evidence == AccessEvidence.BROAD for d in derived)
        assert all(d.confidence == "medium" for d in derived)
        # "other-data" is NOT matched — the prefix genuinely narrowed.
        assert "other-data" not in targets(derived)

    def test_object_level_grant_identifies_the_bucket(self) -> None:
        derived = derive_access_edges([allow(["arn:aws:s3:::acme-reports/*"])], BUCKETS)
        assert targets(derived) == ["acme-reports"]

    def test_exact_beats_broad_for_the_same_resource(self) -> None:
        grants = [allow(["arn:aws:s3:::acme-*"]), allow(["arn:aws:s3:::acme-reports"])]
        derived = {d.target: d for d in derive_access_edges(grants, BUCKETS)}
        assert derived[ResourceId("acme-reports")].evidence == AccessEvidence.EXACT

    def test_results_are_sorted(self) -> None:
        derived = derive_access_edges([allow(["arn:aws:s3:::acme-*"])], BUCKETS)
        assert targets(derived) == sorted(targets(derived))


class TestDenyPrecedence:
    def test_explicit_deny_removes_an_allowed_resource(self) -> None:
        grants = [allow(["arn:aws:s3:::acme-*"]), deny(["arn:aws:s3:::acme-logs"])]
        # Getting this backwards would report access the principal does
        # not have — the most consequential IAM evaluation mistake.
        assert targets(derive_access_edges(grants, BUCKETS)) == ["acme-reports"]

    def test_broad_deny_removes_everything_it_covers(self) -> None:
        grants = [allow(["arn:aws:s3:::acme-*"]), deny(["arn:aws:s3:::acme-*"])]
        assert derive_access_edges(grants, BUCKETS) == ()

    def test_deny_alone_produces_nothing(self) -> None:
        assert derive_access_edges([deny(["arn:aws:s3:::acme-reports"])], BUCKETS) == ()


class TestConditions:
    def test_a_conditioned_grant_is_downgraded_not_dropped(self) -> None:
        grant = allow(["arn:aws:s3:::acme-reports"], has_condition=True)
        derived = derive_access_edges([grant], BUCKETS)

        # The access may well be real — we simply cannot evaluate
        # aws:SourceIp without request context. So: still an edge, one
        # confidence level lower.
        assert targets(derived) == ["acme-reports"]
        assert derived[0].confidence == "medium"
        assert derived[0].conditioned is True

    def test_a_conditioned_broad_grant_drops_to_low(self) -> None:
        grant = allow(["arn:aws:s3:::acme-*"], has_condition=True)
        assert derive_access_edges([grant], BUCKETS)[0].confidence == "low"


class TestEdgeCases:
    def test_no_grants_produces_nothing(self) -> None:
        assert derive_access_edges([], BUCKETS) == ()

    def test_no_candidates_produces_nothing(self) -> None:
        assert derive_access_edges([allow(["*"])], []) == ()

    def test_non_matching_pattern_produces_nothing(self) -> None:
        assert derive_access_edges([allow(["arn:aws:s3:::nothing-here"])], BUCKETS) == ()

    def test_case_insensitive_matching(self) -> None:
        derived = derive_access_edges([allow(["arn:aws:s3:::ACME-REPORTS"])], BUCKETS)
        assert targets(derived) == ["acme-reports"]

    def test_question_mark_wildcard(self) -> None:
        assert pattern_matches("acme-log?", "acme-logs")


class TestGrantRehydration:
    def test_mappings_become_grants(self) -> None:
        grants = grants_from_mappings(
            [
                {
                    "effect": "Allow",
                    "actions": ["s3:*"],
                    "resources": ["arn:aws:s3:::acme-reports"],
                    "has_condition": True,
                    "condition_keys": ["aws:SourceIp"],
                }
            ]
        )
        assert len(grants) == 1
        assert grants[0].is_allow
        assert grants[0].has_condition is True

    @pytest.mark.parametrize("bad", [None, "not-a-list", 42, [None], ["str"]])
    def test_malformed_input_is_ignored_not_crashed(self, bad) -> None:
        # UNKNOWN lands here when policy enumeration was denied. It must
        # degrade to "no grants", never to an exception mid-scan.
        assert grants_from_mappings(bad) == () or all(
            g.effect == "" for g in grants_from_mappings(bad)
        )
