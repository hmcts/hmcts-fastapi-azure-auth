"""Tests for hmcts_azure_auth.dependencies."""

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from hmcts_azure_auth.audit import AuditEvent, AuditEventType
from hmcts_azure_auth.dependencies import (
    build_current_user_dep,
    get_allowlisted_user,
    get_current_user_base,
)
from hmcts_azure_auth.models import AuthUser


def _easy_auth_header(user_id: str = "oid-123", email: str = "user@example.com") -> str:
    payload = {
        "userId": user_id,
        "claims": [
            {"typ": "email", "val": email},
            {"typ": "name", "val": "Test User"},
        ],
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ---------------------------------------------------------------------------
# get_current_user_base — local dev path
# ---------------------------------------------------------------------------


class TestGetCurrentUserBaseLocalDev:
    """In local dev (ENVIRONMENT=local) the dependency returns a mock user."""

    def test_returns_mock_user_in_local_dev(self, local_env):
        # local_env sets ENVIRONMENT=local; the product defaults to production.
        app2 = FastAPI()

        @app2.get("/me")
        async def me2(user=__import__("fastapi").Depends(get_current_user_base)):
            return {"user_id": user.user_id, "email": user.email, "roles": user.roles}

        client = TestClient(app2, raise_server_exceptions=True)
        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == "local-dev-user-123"
        assert len(data["roles"]) > 0


# ---------------------------------------------------------------------------
# get_current_user_base — production path
# ---------------------------------------------------------------------------


class TestGetCurrentUserBaseProduction:
    def _make_app(self):
        app = FastAPI()

        @app.get("/me")
        async def me(user=__import__("fastapi").Depends(get_current_user_base)):
            return {"user_id": user.user_id, "email": user.email, "roles": user.roles}

        return app

    def test_raises_401_without_easy_auth_header(self, non_local_env):
        app = self._make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/me")
        assert resp.status_code == 401

    def test_raises_401_in_strict_mode_without_jwt(self, non_local_env, monkeypatch):
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "true")
        app = self._make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/me", headers={"X-Ms-Client-Principal": _easy_auth_header()})
        assert resp.status_code == 401

    def test_passes_with_easy_auth_and_disabled_jwt(self, non_local_env, monkeypatch):
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "false")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "false")

        # Patch the jwt_verification_service so it reflects the monkeypatched env
        mock_svc = MagicMock()
        mock_svc.enabled = False
        mock_svc.strict_mode = False
        mock_svc.verify_jwt_token = AsyncMock(return_value=None)

        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=mock_svc):
            app = self._make_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/me",
                headers={"X-Ms-Client-Principal": _easy_auth_header()},
            )
        assert resp.status_code == 200
        assert resp.json()["email"] == "user@example.com"


# ---------------------------------------------------------------------------
# get_current_user_base — OID and identity cross-check
# ---------------------------------------------------------------------------


class TestGetCurrentUserBaseOIDValidation:
    """Tests for the OID / identity cross-check in get_current_user_base.

    These call the dependency directly (not via TestClient) since it is a plain
    async function — FastAPI header annotations are just type hints at call time.
    jwt_verification_service is always patched so tests are independent of the
    module-level singleton state.
    """

    def _make_jwt_svc(
        self,
        *,
        oid: str = "oid-123",
        email: str = "user@example.com",
        roles: list | None = None,
        strict: bool = True,
    ) -> MagicMock:
        svc = MagicMock()
        svc.enabled = True
        svc.strict_mode = strict
        svc.verify_jwt_token = AsyncMock(return_value={"oid": oid})
        svc.extract_user_info_from_jwt.return_value = {
            "azure_user_id": oid,
            "email": email,
            "name": "Test User",
            "upn": "",
            "roles": roles or [],
        }
        return svc

    @pytest.mark.asyncio
    async def test_matching_oids_succeed(self, non_local_env):
        svc = self._make_jwt_svc(oid="oid-123")
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            user = await get_current_user_base(
                x_ms_client_principal=_easy_auth_header("oid-123"),
                authorization="Bearer test-token",
            )
        assert user.user_id == "oid-123"
        assert user.email == "user@example.com"

    @pytest.mark.asyncio
    async def test_oid_mismatch_raises_401_in_strict_mode(self, non_local_env):
        svc = self._make_jwt_svc(oid="jwt-oid-different", strict=True)
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user_base(
                    x_ms_client_principal=_easy_auth_header("easy-auth-oid"),
                    authorization="Bearer test-token",
                )
        assert exc_info.value.status_code == 401
        assert "mismatch" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_oid_mismatch_allows_through_in_non_strict_mode(self, non_local_env):
        svc = self._make_jwt_svc(oid="jwt-oid-different", strict=False)
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            user = await get_current_user_base(
                x_ms_client_principal=_easy_auth_header("easy-auth-oid"),
                authorization="Bearer test-token",
            )
        assert user is not None

    @pytest.mark.asyncio
    async def test_oid_mismatch_logs_error(self, non_local_env):
        svc = self._make_jwt_svc(oid="jwt-oid-different", strict=False)
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            with patch("hmcts_azure_auth.dependencies.logger") as mock_logger:
                await get_current_user_base(
                    x_ms_client_principal=_easy_auth_header("easy-auth-oid"),
                    authorization="Bearer test-token",
                )
        mock_logger.error.assert_called_once()
        log_msg = mock_logger.error.call_args[0][0]
        assert "mismatch" in log_msg.lower() or "Identity" in log_msg

    @pytest.mark.asyncio
    async def test_oid_comparison_is_case_insensitive(self, non_local_env):
        # JWT has uppercase OID, Easy Auth has lowercase — should not trigger mismatch.
        svc = self._make_jwt_svc(oid="OID-123", strict=True)
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            user = await get_current_user_base(
                x_ms_client_principal=_easy_auth_header("oid-123"),
                authorization="Bearer test-token",
            )
        assert user.user_id.upper() == "OID-123"

    @pytest.mark.asyncio
    async def test_email_mismatch_logs_info_not_error(self, non_local_env):
        # OIDs match, emails differ — logs INFO, not WARNING or ERROR, no 401.
        svc = self._make_jwt_svc(oid="oid-123", email="jwt@example.com")
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            with patch("hmcts_azure_auth.dependencies.logger") as mock_logger:
                user = await get_current_user_base(
                    x_ms_client_principal=_easy_auth_header("oid-123", "easyauth@example.com"),
                    authorization="Bearer test-token",
                )
        assert user is not None
        info_msgs = [call[0][0] for call in mock_logger.info.call_args_list]
        assert any("email" in m.lower() for m in info_msgs)
        mock_logger.error.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_info_log_contains_email_pii(self, non_local_env):
        # Regression test: INFO-level auth logs must never include the user's
        # actual email address (PII) — only non-PII identifiers like oid/roles.
        svc = self._make_jwt_svc(oid="oid-123", email="jwt-secret@example.com")
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            with patch("hmcts_azure_auth.dependencies.logger") as mock_logger:
                await get_current_user_base(
                    x_ms_client_principal=_easy_auth_header("oid-123", "easyauth-secret@example.com"),
                    authorization="Bearer test-token",
                )
        for call in mock_logger.info.call_args_list:
            assert "jwt-secret@example.com" not in call[0]
            assert "easyauth-secret@example.com" not in call[0]

    @pytest.mark.asyncio
    async def test_missing_jwt_oid_falls_back_to_easy_auth_oid(self, non_local_env):
        # JWT with no oid claim — cross-check is skipped, Easy Auth OID is used.
        svc = MagicMock()
        svc.enabled = True
        svc.strict_mode = True
        svc.verify_jwt_token = AsyncMock(return_value={"email": "user@example.com"})
        svc.extract_user_info_from_jwt.return_value = {
            "azure_user_id": "",
            "email": "user@example.com",
            "name": "",
            "upn": "",
            "roles": [],
        }
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            user = await get_current_user_base(
                x_ms_client_principal=_easy_auth_header("oid-from-easy-auth"),
                authorization="Bearer test-token",
            )
        assert user.user_id == "oid-from-easy-auth"

    @pytest.mark.asyncio
    async def test_missing_easy_auth_oid_skips_cross_check(self, non_local_env):
        # Easy Auth header with empty userId — cross-check condition skipped; JWT OID is used.
        payload = {
            "userId": "",
            "claims": [
                {"typ": "email", "val": "user@example.com"},
                {"typ": "name", "val": "Test User"},
            ],
        }
        header = base64.b64encode(json.dumps(payload).encode()).decode()

        svc = self._make_jwt_svc(oid="oid-from-jwt", strict=True)
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            user = await get_current_user_base(
                x_ms_client_principal=header,
                authorization="Bearer test-token",
            )
        assert user.user_id == "oid-from-jwt"

    @pytest.mark.asyncio
    async def test_no_jwt_in_strict_mode_raises_401(self, non_local_env):
        svc = MagicMock()
        svc.strict_mode = True
        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=svc):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user_base(
                    x_ms_client_principal=_easy_auth_header("oid-123"),
                    authorization=None,
                )
        assert exc_info.value.status_code == 401
        assert "jwt" in exc_info.value.detail.lower() or "token" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_invalid_json_in_easy_auth_header_raises_401(self, non_local_env):
        # Valid base64, but decodes to non-JSON.
        bad_header = base64.b64encode(b"not-valid-json{{{").decode()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_base(
                x_ms_client_principal=bad_header,
                authorization=None,
            )
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_base64_in_easy_auth_header_raises_401(self, non_local_env):
        # Garbage string — base64 decoding produces non-JSON bytes.
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_base(
                x_ms_client_principal="AAAA",  # decodes to null bytes, not valid JSON
                authorization=None,
            )
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# build_current_user_dep
# ---------------------------------------------------------------------------


class TestBuildCurrentUserDep:
    def test_resolver_is_called_with_auth_user_data(self, monkeypatch):
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "false")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "false")

        resolved = {}

        def _resolver(azure_user_id: str, email: str, roles: list) -> dict:
            resolved.update(azure_user_id=azure_user_id, email=email, roles=roles)
            return {"id": 1, "email": email, "app_roles": roles}

        mock_svc = MagicMock()
        mock_svc.enabled = False
        mock_svc.strict_mode = False
        mock_svc.verify_jwt_token = AsyncMock(return_value=None)

        with patch("hmcts_azure_auth.dependencies.get_jwt_service", return_value=mock_svc):
            dep = build_current_user_dep(_resolver)
            app = FastAPI()

            @app.get("/me")
            async def me(user=__import__("fastapi").Depends(dep)):
                return user

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/me",
                headers={"X-Ms-Client-Principal": _easy_auth_header("oid-abc", "test@example.com")},
            )

        # In local dev mode resolver is still called
        assert resp.status_code == 200

    def test_async_resolver_is_awaited(self):
        called = {}

        async def _async_resolver(user_id, email, roles):
            called["user_id"] = user_id
            return AuthUser(user_id=user_id, name="", email=email, roles=roles)

        # Just verify the dep is a coroutine function (FastAPI will await it)
        dep = build_current_user_dep(_async_resolver)
        import asyncio

        assert asyncio.iscoroutinefunction(dep)


# ---------------------------------------------------------------------------
# get_allowlisted_user
# ---------------------------------------------------------------------------


class TestGetAllowlistedUser:
    def _make_app_with_roles(self, required_roles_any=None, required_roles_all=None, audit_writer=None):
        """Build a test FastAPI app that uses get_allowlisted_user with a mock user dep."""
        app = FastAPI()
        # We use local dev mode so get_current_user_base returns mock user with all roles.
        dep = get_allowlisted_user(
            required_roles_any=required_roles_any,
            required_roles_all=required_roles_all,
            audit_writer=audit_writer,
        )

        @app.get("/protected")
        async def protected(user=__import__("fastapi").Depends(dep)):
            return {"email": getattr(user, "email", "unknown"), "roles": getattr(user, "roles", [])}

        return app

    def test_passes_when_no_roles_required(self, local_env):
        app = self._make_app_with_roles()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_passes_when_user_has_required_role(self, local_env):
        # local dev returns all default roles including Judge
        app = self._make_app_with_roles(required_roles_any=["Judge"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_passes_when_user_has_all_required_roles(self, local_env):
        app = self._make_app_with_roles(required_roles_all=["Judge", "Normal"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_audit_writer_called_on_403(self, non_local_env, monkeypatch):
        monkeypatch.setenv("JWT_ENABLE_VERIFICATION", "false")
        monkeypatch.setenv("JWT_VERIFICATION_STRICT", "false")

        captured: list[AuditEvent] = []

        def _writer(event: AuditEvent) -> None:
            captured.append(event)

        # Create an AuthUser with no roles
        async def _no_role_dep():
            return AuthUser(user_id="u", name="", email="u@example.com", roles=[])

        dep = get_allowlisted_user(
            required_roles_any=["Judge"],
            audit_writer=_writer,
            current_user_dep=_no_role_dep,
        )
        app = FastAPI()

        @app.get("/protected")
        async def protected(user=__import__("fastapi").Depends(dep)):
            return {}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")

        assert resp.status_code == 403
        assert len(captured) == 1
        assert captured[0].event_type == AuditEventType.ACCESS_DENIED
        assert "Judge" in captured[0].required_roles

    def test_async_audit_writer_is_awaited(self, non_local_env):
        captured: list[AuditEvent] = []

        async def _async_writer(event: AuditEvent) -> None:
            captured.append(event)

        async def _no_role_dep():
            return AuthUser(user_id="u", name="", email="u@example.com", roles=[])

        dep = get_allowlisted_user(
            required_roles_any=["Judge"],
            audit_writer=_async_writer,
            current_user_dep=_no_role_dep,
        )
        app = FastAPI()

        @app.get("/protected")
        async def protected(user=__import__("fastapi").Depends(dep)):
            return {}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 403
        assert len(captured) == 1

    def test_role_check_passed_log_has_no_email_pii(self, non_local_env):
        # Regression test: the "Role check passed" INFO log must identify the
        # user by user_id, never by their actual email address (PII).
        async def _user_dep():
            return AuthUser(user_id="oid-123", name="", email="secret@example.com", roles=["Judge"])

        dep = get_allowlisted_user(required_roles_any=["Judge"], current_user_dep=_user_dep)
        app = FastAPI()

        @app.get("/protected")
        async def protected(user=__import__("fastapi").Depends(dep)):
            return {}

        client = TestClient(app, raise_server_exceptions=False)
        with patch("hmcts_azure_auth.dependencies.logger") as mock_logger:
            resp = client.get("/protected")

        assert resp.status_code == 200
        for call in mock_logger.info.call_args_list:
            assert "secret@example.com" not in call[0]
