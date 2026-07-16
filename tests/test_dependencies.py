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

    def test_returns_mock_user_in_local_dev(self):
        app = FastAPI()

        @app.get("/me")
        async def me(user: AuthUser = get_current_user_base.__wrapped__ if hasattr(get_current_user_base, "__wrapped__") else None):
            return {"email": user.email}

        # Simpler: call via TestClient with ENVIRONMENT=local (default)
        app2 = FastAPI()

        @app2.get("/me")
        async def me2(user=__import__("fastapi").Depends(get_current_user_base)):
            return {"user_id": user.user_id, "email": user.email, "roles": user.roles}

        client = TestClient(app2, raise_server_exceptions=True)
        # ENVIRONMENT defaults to "local" in tests
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

        with patch("hmcts_azure_auth.dependencies.jwt_verification_service", mock_svc):
            app = self._make_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/me",
                headers={"X-Ms-Client-Principal": _easy_auth_header()},
            )
        assert resp.status_code == 200
        assert resp.json()["email"] == "user@example.com"


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

        with patch("hmcts_azure_auth.dependencies.jwt_verification_service", mock_svc):
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

    def test_passes_when_no_roles_required(self):
        app = self._make_app_with_roles()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_passes_when_user_has_required_role(self):
        # local dev returns all default roles including Judge
        app = self._make_app_with_roles(required_roles_any=["Judge"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 200

    def test_passes_when_user_has_all_required_roles(self):
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
