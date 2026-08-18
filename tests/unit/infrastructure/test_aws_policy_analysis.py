from infrastructure.cloud.aws.policy_analysis import policy_allows_public_principal, policy_grants_full_admin


class TestPolicyAllowsPublicPrincipal:
    def test_none_document_is_not_public(self) -> None:
        assert policy_allows_public_principal(None) is False

    def test_empty_document_is_not_public(self) -> None:
        assert policy_allows_public_principal({}) is False

    def test_wildcard_string_principal_is_public(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
        assert policy_allows_public_principal(document) is True

    def test_wildcard_aws_principal_is_public(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}]}
        assert policy_allows_public_principal(document) is True

    def test_wildcard_aws_principal_in_list_is_public(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::123:root", "*"]}}]}
        assert policy_allows_public_principal(document) is True

    def test_deny_statement_does_not_count(self) -> None:
        document = {"Statement": [{"Effect": "Deny", "Principal": "*"}]}
        assert policy_allows_public_principal(document) is False

    def test_scoped_principal_is_not_public(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}]}
        assert policy_allows_public_principal(document) is False

    def test_conditioned_wildcard_principal_is_treated_conservatively_as_not_public(self) -> None:
        document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
                }
            ]
        }
        assert policy_allows_public_principal(document) is False

    def test_single_statement_not_wrapped_in_a_list_is_supported(self) -> None:
        document = {"Statement": {"Effect": "Allow", "Principal": "*"}}
        assert policy_allows_public_principal(document) is True

    def test_multiple_statements_any_public_is_enough(self) -> None:
        document = {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}},
                {"Effect": "Allow", "Principal": "*"},
            ]
        }
        assert policy_allows_public_principal(document) is True


class TestPolicyGrantsFullAdmin:
    def test_none_document_is_not_admin(self) -> None:
        assert policy_grants_full_admin(None) is False

    def test_wildcard_action_and_resource_is_admin(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        assert policy_grants_full_admin(document) is True

    def test_wildcard_action_in_list_and_resource_is_admin(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}]}
        assert policy_grants_full_admin(document) is True

    def test_scoped_action_is_not_admin(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        assert policy_grants_full_admin(document) is False

    def test_scoped_resource_is_not_admin(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}]}
        assert policy_grants_full_admin(document) is False

    def test_deny_statement_does_not_count(self) -> None:
        document = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        assert policy_grants_full_admin(document) is False
