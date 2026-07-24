"""Tests for hmcts_azure_auth.jwt — JWTVerificationService."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from hmcts_azure_auth.jwt import JWTVerificationService


@pytest.fixture()
def service_disabled(monkeypatch):
    monkeypatch.setenv("AZURE_AD_TENANT_ID", "")
    monkeypatch.setenv("AZURE_AD_CLIENT_ID", "")
    monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "false")
    return JWTVerificationService()


@pytest.fixture()
def service_no_tenant(monkeypatch):
    """Verification enabled but no tenant — JWKS client not created."""
    monkeypatch.setenv("AZURE_AD_TENANT_ID", "")
    monkeypatch.setenv("AZURE_AD_CLIENT_ID", "test-client")
    monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
    monkeypatch.setenv("JWT_VERIFICATION_STRICT", "false")
    return JWTVerificationService()


class TestJWTVerificationServiceInit:
    def test_disabled_when_env_false(self, service_disabled):
        assert service_disabled.enabled is False
        assert service_disabled.jwks_client is None

    def test_no_jwks_client_when_tenant_empty(self, service_no_tenant):
        assert service_no_tenant.jwks_client is None


class TestVerifyJWTToken:
    async def test_returns_none_when_disabled(self, service_disabled):
        result = await service_disabled.verify_jwt_token("any.token.here")
        assert result is None

    async def test_returns_none_for_empty_token_non_strict(self, service_no_tenant):
        result = await service_no_tenant.verify_jwt_token("")
        assert result is None

    async def test_raises_401_for_empty_token_strict(self, monkeypatch):
        monkeypatch.setenv("AZURE_AD_TENANT_ID", "tenant")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
        svc = JWTVerificationService()
        svc.jwks_client = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await svc.verify_jwt_token("")
        assert exc_info.value.status_code == 401

    async def test_returns_none_when_no_jwks_client_non_strict(self, service_no_tenant):
        result = await service_no_tenant.verify_jwt_token("some.token")
        assert result is None

    async def test_raises_500_when_no_jwks_client_strict(self, monkeypatch):
        monkeypatch.setenv("AZURE_AD_TENANT_ID", "")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
        svc = JWTVerificationService()
        with pytest.raises(HTTPException) as exc_info:
            await svc.verify_jwt_token("some.token")
        assert exc_info.value.status_code == 500

    async def test_returns_decoded_on_valid_token(self, monkeypatch):
        monkeypatch.setenv("AZURE_AD_TENANT_ID", "tenant")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        svc = JWTVerificationService()
        mock_jwks = MagicMock()
        mock_key = MagicMock()
        mock_jwks.get_signing_key_from_jwt.return_value = MagicMock(key=mock_key)
        svc.jwks_client = mock_jwks

        decoded_payload = {"oid": "user-123", "email": "user@example.com", "roles": ["Judge"]}
        with patch("hmcts_azure_auth.jwt.jwt.decode", return_value=decoded_payload):
            result = await svc.verify_jwt_token("valid.jwt.token")

        assert result == decoded_payload

    async def test_success_log_does_not_contain_email(self, monkeypatch):
        # Regression test: the success-path INFO log must identify the user by
        # the non-PII Azure AD oid, never by email/preferred_username.
        monkeypatch.setenv("AZURE_AD_TENANT_ID", "tenant")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        svc = JWTVerificationService()
        mock_jwks = MagicMock()
        mock_jwks.get_signing_key_from_jwt.return_value = MagicMock(key=MagicMock())
        svc.jwks_client = mock_jwks

        decoded_payload = {
            "oid": "user-oid-123",
            "email": "secret@example.com",
            "roles": ["Judge"],
        }
        with patch("hmcts_azure_auth.jwt.jwt.decode", return_value=decoded_payload):
            with patch("hmcts_azure_auth.jwt.logger") as mock_logger:
                result = await svc.verify_jwt_token("valid.jwt.token")

        assert result == decoded_payload
        for call in mock_logger.info.call_args_list:
            assert "secret@example.com" not in call[0]
        assert any("user-oid-123" in call[0] for call in mock_logger.info.call_args_list)

    async def test_raises_401_on_expired_token_strict(self, monkeypatch):
        import jwt as _jwt

        monkeypatch.setenv("AZURE_AD_TENANT_ID", "tenant")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
        svc = JWTVerificationService()
        mock_jwks = MagicMock()
        mock_jwks.get_signing_key_from_jwt.return_value = MagicMock(key=MagicMock())
        svc.jwks_client = mock_jwks

        with patch("hmcts_azure_auth.jwt.jwt.decode", side_effect=_jwt.ExpiredSignatureError):
            with pytest.raises(HTTPException) as exc_info:
                await svc.verify_jwt_token("expired.token")
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()


class TestExtractUserInfoFromJWT:
    def test_extracts_standard_claims(self):
        svc = JWTVerificationService()
        decoded = {
            "oid": "user-oid",
            "email": "user@example.com",
            "name": "Test User",
            "upn": "upn@example.com",
            "roles": ["Judge", "Normal"],
        }
        info = svc.extract_user_info_from_jwt(decoded)
        assert info["azure_user_id"] == "user-oid"
        assert info["email"] == "user@example.com"
        assert info["name"] == "Test User"
        assert info["roles"] == ["Judge", "Normal"]

    def test_falls_back_to_preferred_username_for_email(self):
        svc = JWTVerificationService()
        info = svc.extract_user_info_from_jwt({"preferred_username": "user@example.com"})
        assert info["email"] == "user@example.com"

    def test_roles_defaults_to_empty_list(self):
        svc = JWTVerificationService()
        info = svc.extract_user_info_from_jwt({})
        assert info["roles"] == []

    def test_non_list_roles_normalised_to_empty(self):
        svc = JWTVerificationService()
        info = svc.extract_user_info_from_jwt({"roles": "Judge"})
        assert info["roles"] == []
