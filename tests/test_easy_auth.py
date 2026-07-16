"""Tests for hmcts_azure_auth.easy_auth."""

import base64
import json

import pytest
from fastapi import HTTPException

from hmcts_azure_auth.easy_auth import parse_easy_auth_header


def _encode(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


class TestParseEasyAuthHeader:
    def _make_header(self, user_id: str, claims: list[dict]) -> str:
        return _encode({"userId": user_id, "claims": claims})

    def test_parses_email_claim(self):
        header = self._make_header(
            "oid-123",
            [{"typ": "email", "val": "user@example.com"}],
        )
        identity = parse_easy_auth_header(header)
        assert identity.email == "user@example.com"
        assert identity.azure_user_id == "oid-123"

    def test_falls_back_to_preferred_username(self):
        header = self._make_header(
            "oid-123",
            [{"typ": "preferred_username", "val": "user@example.com"}],
        )
        identity = parse_easy_auth_header(header)
        assert identity.email == "user@example.com"

    def test_falls_back_to_upn(self):
        header = self._make_header(
            "oid-123",
            [{"typ": "upn", "val": "user@example.com"}],
        )
        identity = parse_easy_auth_header(header)
        assert identity.email == "user@example.com"

    def test_extracts_name_claim(self):
        header = self._make_header(
            "oid-123",
            [
                {"typ": "email", "val": "user@example.com"},
                {"typ": "name", "val": "Test User"},
            ],
        )
        identity = parse_easy_auth_header(header)
        assert identity.name == "Test User"

    def test_name_defaults_to_empty_string_when_absent(self):
        header = self._make_header(
            "oid-123",
            [{"typ": "email", "val": "user@example.com"}],
        )
        identity = parse_easy_auth_header(header)
        assert identity.name == ""

    def test_email_claim_takes_priority_over_upn(self):
        header = self._make_header(
            "oid-123",
            [
                {"typ": "upn", "val": "upn@example.com"},
                {"typ": "email", "val": "email@example.com"},
            ],
        )
        identity = parse_easy_auth_header(header)
        assert identity.email == "email@example.com"

    def test_raises_401_on_missing_email(self):
        header = self._make_header("oid-123", [{"typ": "name", "val": "Test User"}])
        with pytest.raises(HTTPException) as exc_info:
            parse_easy_auth_header(header)
        assert exc_info.value.status_code == 401
        assert "email" in exc_info.value.detail.lower()

    def test_raises_401_on_invalid_base64(self):
        with pytest.raises(HTTPException) as exc_info:
            parse_easy_auth_header("not-valid-base64!!!")
        assert exc_info.value.status_code == 401

    def test_raises_401_on_invalid_json(self):
        bad = base64.b64encode(b"not json").decode()
        with pytest.raises(HTTPException) as exc_info:
            parse_easy_auth_header(bad)
        assert exc_info.value.status_code == 401
