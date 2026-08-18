from botocore.exceptions import ClientError

from infrastructure.cloud.aws.errors import (
    AwsAuthenticationError,
    AwsPermissionError,
    AwsServiceError,
    translate_client_error,
)


def make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "ListBuckets")


class TestTranslateClientError:
    def test_access_denied_becomes_permission_error(self) -> None:
        result = translate_client_error(make_client_error("AccessDenied"), context="list buckets")
        assert isinstance(result, AwsPermissionError)

    def test_unauthorized_operation_becomes_permission_error(self) -> None:
        result = translate_client_error(make_client_error("UnauthorizedOperation"), context="ctx")
        assert isinstance(result, AwsPermissionError)

    def test_invalid_client_token_becomes_authentication_error(self) -> None:
        result = translate_client_error(make_client_error("InvalidClientTokenId"), context="ctx")
        assert isinstance(result, AwsAuthenticationError)

    def test_expired_token_becomes_authentication_error(self) -> None:
        result = translate_client_error(make_client_error("ExpiredToken"), context="ctx")
        assert isinstance(result, AwsAuthenticationError)

    def test_throttling_becomes_service_error(self) -> None:
        result = translate_client_error(make_client_error("Throttling"), context="ctx")
        assert isinstance(result, AwsServiceError)

    def test_unknown_code_becomes_service_error_not_swallowed(self) -> None:
        result = translate_client_error(make_client_error("SomeNewAwsErrorCode"), context="ctx")
        assert isinstance(result, AwsServiceError)

    def test_non_client_error_still_becomes_service_error(self) -> None:
        result = translate_client_error(ConnectionError("network down"), context="ctx")
        assert isinstance(result, AwsServiceError)

    def test_context_and_original_message_are_preserved(self) -> None:
        result = translate_client_error(make_client_error("AccessDenied"), context="listing buckets")
        assert "listing buckets" in str(result)
