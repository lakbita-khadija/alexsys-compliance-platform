from infrastructure.cloud.azure.errors import (
    AzureAuthenticationError,
    AzureCollectionError,
    AzureError,
    AzurePermissionError,
    AzureServiceError,
    translate_azure_error,
)
from infrastructure.errors import InfrastructureError


class FakeHttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


class ClientAuthenticationError(Exception):
    """Deliberately named to match the real Azure SDK class, since
    `translate_azure_error` recognizes it by name — see that function's
    docstring for why it does not import the SDK.
    """


class TestAzureErrorHierarchy:
    def test_every_azure_error_is_an_infrastructure_error(self) -> None:
        for error_class in (
            AzureError,
            AzureAuthenticationError,
            AzurePermissionError,
            AzureServiceError,
            AzureCollectionError,
        ):
            assert issubclass(error_class, InfrastructureError)

    def test_specific_errors_subclass_azure_error(self) -> None:
        for error_class in (
            AzureAuthenticationError,
            AzurePermissionError,
            AzureServiceError,
            AzureCollectionError,
        ):
            assert issubclass(error_class, AzureError)


class TestTranslateAzureError:
    def test_401_is_an_authentication_error(self) -> None:
        result = translate_azure_error(FakeHttpError(401), context="listing storage accounts")
        assert isinstance(result, AzureAuthenticationError)

    def test_403_is_a_permission_error(self) -> None:
        result = translate_azure_error(FakeHttpError(403), context="listing storage accounts")
        assert isinstance(result, AzurePermissionError)

    def test_500_is_a_service_error(self) -> None:
        result = translate_azure_error(FakeHttpError(500), context="listing storage accounts")
        assert isinstance(result, AzureServiceError)

    def test_429_throttling_is_a_service_error(self) -> None:
        result = translate_azure_error(FakeHttpError(429), context="listing storage accounts")
        assert isinstance(result, AzureServiceError)

    def test_client_authentication_error_is_recognized_by_name(self) -> None:
        result = translate_azure_error(ClientAuthenticationError("no credential"), context="authenticating")
        assert isinstance(result, AzureAuthenticationError)

    def test_exception_without_status_code_is_a_service_error(self) -> None:
        result = translate_azure_error(RuntimeError("network unreachable"), context="listing")
        assert isinstance(result, AzureServiceError)

    def test_context_is_preserved_in_the_message(self) -> None:
        result = translate_azure_error(FakeHttpError(403), context="collecting key vaults")
        assert "collecting key vaults" in str(result)

    def test_original_message_is_preserved(self) -> None:
        result = translate_azure_error(FakeHttpError(403), context="collecting key vaults")
        assert "http 403" in str(result)

    def test_translation_never_returns_a_bare_azure_error(self) -> None:
        result = translate_azure_error(RuntimeError("something"), context="x")
        assert type(result) is not AzureError
