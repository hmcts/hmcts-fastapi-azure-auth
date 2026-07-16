"""Tests for hmcts_azure_auth.roles."""

import json
import os

import pytest

from hmcts_azure_auth.roles import (
    DEFAULT_APP_ROLES,
    get_role,
    get_valid_roles,
    has_any_role,
)


class TestDefaultAppRoles:
    def test_contains_judge(self):
        assert "Judge" in DEFAULT_APP_ROLES

    def test_contains_legal_text_manager(self):
        assert "LegalTextManager" in DEFAULT_APP_ROLES

    def test_contains_system_administrator(self):
        assert "SystemAdministrator" in DEFAULT_APP_ROLES

    def test_contains_normal(self):
        assert "Normal" in DEFAULT_APP_ROLES


class TestGetValidRoles:
    def test_returns_defaults_when_no_env_var(self):
        assert get_valid_roles() == DEFAULT_APP_ROLES

    def test_custom_roles_override_defaults(self, monkeypatch):
        custom = {
            "Judge": "Judge",
            "LegalTextManager": "LegalTextManager",
            "SystemAdministrator": "SystemAdministrator",
            "Normal": "Normal",
            "CustomRole": "CustomRole",
        }
        monkeypatch.setenv("AUTH_APPROLES", json.dumps(custom))
        assert get_valid_roles() == custom

    def test_falls_back_on_invalid_json(self, monkeypatch, caplog):
        monkeypatch.setenv("AUTH_APPROLES", "not-json")
        assert get_valid_roles() == DEFAULT_APP_ROLES
        assert "not valid JSON" in caplog.text

    def test_falls_back_on_non_dict(self, monkeypatch, caplog):
        monkeypatch.setenv("AUTH_APPROLES", json.dumps(["Judge"]))
        assert get_valid_roles() == DEFAULT_APP_ROLES
        assert "JSON object" in caplog.text

    def test_falls_back_on_missing_required_keys(self, monkeypatch, caplog):
        monkeypatch.setenv("AUTH_APPROLES", json.dumps({"Judge": "Judge"}))
        assert get_valid_roles() == DEFAULT_APP_ROLES
        assert "missing required keys" in caplog.text

    def test_falls_back_on_non_string_values(self, monkeypatch, caplog):
        bad = {k: 1 for k in DEFAULT_APP_ROLES}
        monkeypatch.setenv("AUTH_APPROLES", json.dumps(bad))
        assert get_valid_roles() == DEFAULT_APP_ROLES
        assert "must all be strings" in caplog.text


class TestHasAnyRole:
    def test_returns_true_for_valid_role(self):
        assert has_any_role(["Judge"]) is True

    def test_returns_true_for_normal_role(self):
        assert has_any_role(["Normal"]) is True

    def test_returns_false_for_no_roles(self):
        assert has_any_role([]) is False

    def test_returns_false_for_unknown_role(self):
        assert has_any_role(["UnknownRole"]) is False

    def test_returns_true_when_one_of_many_is_valid(self):
        assert has_any_role(["UnknownRole", "Judge"]) is True


class TestGetRole:
    def test_returns_value_for_known_role(self):
        assert get_role("Judge") == "Judge"

    def test_returns_value_for_normal(self):
        assert get_role("Normal") == "Normal"

    def test_returns_none_for_unknown_role(self):
        assert get_role("NonExistentRole") is None
