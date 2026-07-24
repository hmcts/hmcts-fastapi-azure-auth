"""Tests for hmcts_azure_auth.jwt — JWTVerificationService.

The verification tests use REAL RS256 cryptography: a real RSA keypair signs real
tokens, and only the external JWKS *network fetch* is stubbed (returning the real
public key). The signature / algorithm-pinning / audience / issuer / expiry checks
run for real — so a regression that weakened them (dropping `algorithms=["RS256"]`,
the `audience`/`issuer` args, or `verify_signature`) turns these tests red. A mock
of `jwt.decode` could not: it would keep passing while the library stopped verifying.
"""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from hmcts_azure_auth.jwt import JWTVerificationService

TENANT = "test-tenant-id"
CLIENT = "test-client-id"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


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


# ---------------------------------------------------------------------------
# Real-crypto fixtures: a genuine RSA keypair + a service whose ONLY stubbed
# part is the JWKS fetch. Everything the library asserts about a token is
# verified for real.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_rs256_token(
    private_key,
    *,
    audience: str = CLIENT,
    issuer: str = ISSUER,
    expires_in: timedelta = timedelta(minutes=5),
    extra: dict | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "oid": "user-oid-123",
        "email": "user@example.com",
        "roles": ["Judge"],
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, private_key, algorithm="RS256")


def _make_service(public_key, *, strict: bool) -> JWTVerificationService:
    svc = JWTVerificationService()
    # Stub ONLY the external boundary — the JWKS HTTP fetch to Azure. The
    # returned signing key is the REAL public key, so jwt.decode runs a real
    # RS256 signature + claims verification.
    svc.jwks_client = MagicMock()
    svc.jwks_client.get_signing_key_from_jwt.return_value = SimpleNamespace(key=public_key)
    svc.strict_mode = strict
    return svc


@pytest.fixture()
def real_service(monkeypatch, rsa_keypair):
    _, public_key = rsa_keypair
    monkeypatch.setenv("AZURE_AD_TENANT_ID", TENANT)
    monkeypatch.setenv("AZURE_AD_CLIENT_ID", CLIENT)
    monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
    monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
    return _make_service(public_key, strict=True)


class TestJWTVerificationServiceInit:
    def test_disabled_when_env_false(self, service_disabled):
        assert service_disabled.enabled is False
        assert service_disabled.jwks_client is None

    def test_no_jwks_client_when_tenant_empty(self, service_no_tenant):
        assert service_no_tenant.jwks_client is None


class TestVerifyJWTTokenControlFlow:
    """Control-flow paths that need no crypto (enabled/tenant/empty-token gates)."""

    async def test_returns_none_when_disabled(self, service_disabled):
        assert await service_disabled.verify_jwt_token("any.token.here") is None

    async def test_returns_none_for_empty_token_non_strict(self, service_no_tenant):
        assert await service_no_tenant.verify_jwt_token("") is None

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
        assert await service_no_tenant.verify_jwt_token("some.token") is None

    async def test_raises_500_when_no_jwks_client_strict(self, monkeypatch):
        monkeypatch.setenv("AZURE_AD_TENANT_ID", "")
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", "client")
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
        svc = JWTVerificationService()
        with pytest.raises(HTTPException) as exc_info:
            await svc.verify_jwt_token("some.token")
        assert exc_info.value.status_code == 500


class TestVerifyJWTTokenRealCrypto:
    """Real RS256 verification — the library's core security guarantee."""

    async def test_valid_token_accepted(self, real_service, rsa_keypair):
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key)
        result = await real_service.verify_jwt_token(token)
        assert result is not None
        assert result["oid"] == "user-oid-123"
        assert result["roles"] == ["Judge"]

    async def test_expired_token_rejected(self, real_service, rsa_keypair):
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key, expires_in=timedelta(minutes=-5))
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    async def test_wrong_audience_rejected(self, real_service, rsa_keypair):
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key, audience="some-other-client")
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "audience" in exc_info.value.detail.lower()

    async def test_wrong_issuer_rejected(self, real_service, rsa_keypair):
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key, issuer="https://login.microsoftonline.com/evil/v2.0")
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "issuer" in exc_info.value.detail.lower()

    async def test_tampered_signature_rejected(self, real_service, rsa_keypair):
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key)
        # Flip the FIRST character of the signature segment — that char encodes
        # the top bits of the first signature byte, so the decoded bytes always
        # change (flipping the last char can hit only padding bits and leave the
        # signature unchanged — a flaky test).
        head, body, sig = token.split(".")
        tampered = f"{head}.{body}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}"
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(tampered)
        assert exc_info.value.status_code == 401

    async def test_signed_by_a_different_key_rejected(self, real_service):
        # A token correctly signed, but by an attacker's key — must fail against
        # the real public key from the JWKS.
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = _make_rs256_token(attacker_key)
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    async def test_alg_none_rejected(self, real_service):
        # Unsigned "alg: none" token — the classic downgrade attack. RS256
        # pinning must reject it.
        def _b64(obj: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

        now = datetime.now(UTC)
        header = _b64({"alg": "none", "typ": "JWT"})
        payload = _b64(
            {
                "aud": CLIENT,
                "iss": ISSUER,
                "exp": int((now + timedelta(minutes=5)).timestamp()),
                "oid": "attacker",
            }
        )
        token = f"{header}.{payload}."  # empty signature
        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    async def test_hs256_algorithm_confusion_rejected(self, real_service, rsa_keypair):
        # RS256->HS256 confusion: an attacker forges an HS256 token using the
        # PUBLIC key bytes (which are, by definition, public) as the HMAC secret.
        # A library that didn't PIN the algorithm to RS256 would accept it. We
        # hand-craft it because PyJWT itself refuses to *encode* one — but a
        # verifier that allowed HS256 would still *accept* it, so the pinning is
        # what protects us. This test locks that pinning in.
        _, public_key = rsa_keypair
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        def _b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        now = datetime.now(UTC)
        header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64(
            json.dumps(
                {
                    "aud": CLIENT,
                    "iss": ISSUER,
                    "exp": int((now + timedelta(minutes=5)).timestamp()),
                    "oid": "attacker",
                }
            ).encode()
        )
        signing_input = f"{header}.{payload}".encode()
        signature = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
        forged = f"{header}.{payload}.{_b64(signature)}"

        with pytest.raises(HTTPException) as exc_info:
            await real_service.verify_jwt_token(forged)
        assert exc_info.value.status_code == 401

    async def test_non_strict_returns_none_on_invalid(self, monkeypatch, rsa_keypair):
        # Non-strict mode swallows failures (returns None) instead of raising —
        # verify that an EXPIRED token yields None, not a decoded payload.
        _, public_key = rsa_keypair
        private_key = rsa_keypair[0]
        monkeypatch.setenv("AZURE_AD_TENANT_ID", TENANT)
        monkeypatch.setenv("AZURE_AD_CLIENT_ID", CLIENT)
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "true")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "false")
        svc = _make_service(public_key, strict=False)
        token = _make_rs256_token(private_key, expires_in=timedelta(minutes=-5))
        assert await svc.verify_jwt_token(token) is None

    async def test_success_log_uses_oid_not_email(self, real_service, rsa_keypair):
        # Regression: the success-path INFO log must identify the user by the
        # non-PII oid, never by email/preferred_username.
        private_key, _ = rsa_keypair
        token = _make_rs256_token(private_key, extra={"email": "secret@example.com"})
        with patch("hmcts_azure_auth.jwt.logger") as mock_logger:
            result = await real_service.verify_jwt_token(token)
        assert result is not None
        for call in mock_logger.info.call_args_list:
            assert "secret@example.com" not in str(call)
        assert any("user-oid-123" in str(call) for call in mock_logger.info.call_args_list)


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
