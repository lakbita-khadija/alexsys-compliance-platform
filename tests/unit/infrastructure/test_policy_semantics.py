"""Tests for semantic IAM policy and trust analysis (§4.1, §5).

These cover the cases that separate real CSPM reasoning from name
matching. Several assert the *absence* of a finding, which matters just
as much: a rule that fires on a correctly-restricted role is a false
positive, and false positives are what get a CSPM switched off.
"""

from __future__ import annotations

import pytest

from infrastructure.cloud.aws.policy_analysis import (
    action_matches,
    analyze_policy_documents,
    analyze_trust_policy,
    policy_allows_public_principal,
    policy_grants_full_admin,
    to_attributes,
)

ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


class TestActionMatching:
    @pytest.mark.parametrize(
        "pattern,action,expected",
        [
            ("*", "iam:PassRole", True),
            ("iam:*", "iam:PassRole", True),
            ("iam:Pass*", "iam:PassRole", True),
            ("iam:PassRole", "iam:PassRole", True),
            ("s3:*", "iam:PassRole", False),
            ("iam:Get*", "iam:PassRole", False),
            # IAM matching is case-insensitive.
            ("IAM:PASSROLE", "iam:passrole", True),
            # `?` is a single-character wildcard.
            ("iam:PassRol?", "iam:PassRole", True),
        ],
    )
    def test_wildcards(self, pattern, action, expected) -> None:
        assert action_matches(pattern, action) is expected

    def test_regex_metacharacters_are_escaped(self) -> None:
        # A `.` in a pattern must match a literal dot, not any character
        # — otherwise patterns would match actions AWS would not.
        assert action_matches("s3:Get.Object", "s3:GetXObject") is False

    def test_bracket_sequences_are_not_treated_as_classes(self) -> None:
        # IAM has no [seq] syntax; fnmatch would wrongly accept this.
        assert action_matches("iam:[GP]etRole", "iam:GetRole") is False


class TestPolicyAnalysis:
    def test_administrator_is_detected_from_statements_not_names(self) -> None:
        # The point: a policy named "DeveloperAccess" granting *:* is
        # still admin, and name matching would miss it entirely.
        analysis = analyze_policy_documents([ADMIN])
        assert analysis.is_administrator is True
        assert analysis.has_wildcard_action is True
        assert analysis.has_wildcard_resource is True

    def test_a_scoped_policy_is_not_administrator(self) -> None:
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}]
        )
        assert analysis.is_administrator is False
        assert analysis.escalation_groups == ()

    def test_not_action_inverts_the_grant(self) -> None:
        # `NotAction: iam:*` grants EVERYTHING except IAM. A naive reader
        # sees "iam" and concludes the opposite.
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}]
        )
        assert "iam:PassRole" not in analysis.dangerous_actions
        # ...but it does grant unrelated escalation-adjacent actions.
        assert analysis.has_wildcard_resource is True

    def test_not_action_grants_actions_outside_the_exclusion(self) -> None:
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]}]
        )
        # iam:* is not excluded, so escalation actions ARE granted.
        assert "policy_attachment" in analysis.escalation_groups

    def test_explicit_deny_beats_allow(self) -> None:
        # AWS semantics: Deny always wins regardless of order. Ignoring
        # it overstates severity.
        analysis = analyze_policy_documents(
            [
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
                    ]
                }
            ]
        )
        assert "iam:CreateAccessKey" not in analysis.dangerous_actions

    def test_deny_ordering_does_not_matter(self) -> None:
        reversed_order = analyze_policy_documents(
            [
                {
                    "Statement": [
                        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    ]
                }
            ]
        )
        assert "iam:CreateAccessKey" not in reversed_order.dangerous_actions

    def test_escalation_groups_are_identified(self) -> None:
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}]}]
        )
        assert "policy_attachment" in analysis.escalation_groups
        assert "iam:AttachRolePolicy" in analysis.dangerous_actions

    def test_pass_role_alone_is_not_flagged_as_escalation(self) -> None:
        # PassRole is normal and necessary. Flagging it alone would fire
        # on a large fraction of legitimate roles.
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}]
        )
        assert analysis.has_pass_role_escalation is False

    def test_pass_role_with_a_compute_action_is_escalation(self) -> None:
        analysis = analyze_policy_documents(
            [
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
                    ]
                }
            ]
        )
        assert analysis.has_pass_role_escalation is True

    def test_escalation_is_detected_across_separate_documents(self) -> None:
        # Permissions are additive: PassRole in an attached policy and
        # RunInstances in an inline one is still an escalation path.
        analysis = analyze_policy_documents(
            [
                {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
                {"Statement": [{"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"}]},
            ]
        )
        assert analysis.has_pass_role_escalation is True

    def test_conditions_reduce_confidence(self) -> None:
        analysis = analyze_policy_documents(
            [
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
                        }
                    ]
                }
            ]
        )
        assert analysis.is_administrator is True
        assert analysis.confidence == "medium", "an org restriction may make this safe"
        assert "aws:PrincipalOrgID" in analysis.constraining_conditions

    def test_a_malformed_statement_does_not_abort_analysis(self) -> None:
        analysis = analyze_policy_documents(
            [{"Statement": ["not-a-statement", {"Effect": "Allow", "Action": "*", "Resource": "*"}]}]
        )
        assert analysis.is_administrator is True
        assert analysis.unparsed_statements == 1

    def test_an_empty_or_absent_document_is_safe(self) -> None:
        assert analyze_policy_documents([]).is_administrator is False
        assert analyze_policy_documents([None]).statement_count == 0
        assert analyze_policy_documents(["garbage"]).statement_count == 0

    def test_not_resource_counts_as_wildcard_resource(self) -> None:
        analysis = analyze_policy_documents(
            [{"Statement": [{"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::x"}]}]
        )
        assert analysis.has_wildcard_resource is True


class TestTrustAnalysis:
    def test_wildcard_principal_without_condition_is_publicly_assumable(self) -> None:
        trust = analyze_trust_policy(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
        )
        assert trust.has_wildcard_principal is True
        assert trust.is_publicly_assumable is True

    def test_wildcard_principal_with_a_condition_is_not_public(self) -> None:
        # The false-positive case. An org-scoped wildcard is a normal,
        # safe pattern; flagging it as "anyone can assume this" would be
        # wrong and would train users to ignore the rule.
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                    }
                ]
            }
        )
        assert trust.has_wildcard_principal is True
        assert trust.is_publicly_assumable is False
        assert "aws:PrincipalOrgID" in trust.constraining_conditions

    def test_external_account_requires_knowing_our_own(self) -> None:
        document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        # Without own_account_id, "external" is unknowable — reported
        # conservatively rather than guessed, or the rule would fire on
        # every role in the account.
        assert analyze_trust_policy(document).has_external_account_principal is False

        trust = analyze_trust_policy(document, own_account_id="111111111111")
        assert trust.has_external_account_principal is True
        assert trust.external_account_ids == ("999999999999",)

    def test_trusting_our_own_account_is_not_external(self) -> None:
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
            own_account_id="111111111111",
        )
        assert trust.has_external_account_principal is False

    def test_service_principal_without_source_pinning_is_confused_deputy(self) -> None:
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            }
        )
        assert trust.has_service_principal is True
        assert trust.has_confused_deputy_risk is True

    def test_source_arn_removes_the_confused_deputy_risk(self) -> None:
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-bucket"}},
                    }
                ]
            }
        )
        assert trust.has_confused_deputy_risk is False

    def test_source_account_also_removes_it(self) -> None:
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"aws:SourceAccount": "111111111111"}},
                    }
                ]
            }
        )
        assert trust.has_confused_deputy_risk is False

    def test_federated_principal_is_detected(self) -> None:
        trust = analyze_trust_policy(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Federated": "arn:aws:iam::111111111111:saml-provider/Okta"},
                        "Action": "sts:AssumeRoleWithSAML",
                    }
                ]
            }
        )
        assert trust.has_federated_principal is True

    def test_a_bare_12_digit_account_is_recognized(self) -> None:
        trust = analyze_trust_policy(
            {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "999999999999"}, "Action": "sts:AssumeRole"}]},
            own_account_id="111111111111",
        )
        assert trust.external_account_ids == ("999999999999",)

    def test_an_empty_trust_policy_is_safe(self) -> None:
        trust = analyze_trust_policy(None)
        assert trust.is_publicly_assumable is False
        assert trust.statement_count == 0


class TestAttributeProjection:
    def test_attributes_are_flat_and_rule_friendly(self) -> None:
        attributes = to_attributes(
            analyze_policy_documents([ADMIN]),
            analyze_trust_policy(
                {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
            ),
        )
        assert attributes["has_administrator_access"] is True
        assert attributes["is_publicly_assumable"] is True
        # Every value must be YAML-rule-matchable without navigating
        # nested structures.
        assert all(
            isinstance(v, (bool, int, str, list)) for v in attributes.values()
        )

    def test_trust_attributes_are_omitted_when_not_analyzed(self) -> None:
        attributes = to_attributes(analyze_policy_documents([ADMIN]))
        assert "is_publicly_assumable" not in attributes


class TestBackwardCompatibility:
    """§40 — the legacy helpers must keep their exact old semantics."""

    def test_legacy_public_principal_still_works(self) -> None:
        assert policy_allows_public_principal({"Statement": [{"Effect": "Allow", "Principal": "*"}]}) is True

    def test_legacy_treats_any_condition_as_not_public(self) -> None:
        # Deliberately different from the new analysis, which reports it
        # with reduced confidence instead. Both are correct for their
        # callers; rewriting one in terms of the other would silently
        # change what 68 shipped rules mean.
        document = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Condition": {"StringEquals": {"aws:SourceIp": "1.2.3.4"}}}
            ]
        }
        assert policy_allows_public_principal(document) is False
        assert analyze_trust_policy(document).has_wildcard_principal is True

    def test_legacy_full_admin_still_works(self) -> None:
        assert policy_grants_full_admin(ADMIN) is True
        assert policy_grants_full_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}) is False
