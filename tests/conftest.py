"""Shared fixtures and cache-clearing for the test suite."""

import pytest

from hmcts_azure_auth.models import get_auth_settings
from hmcts_azure_auth.roles import get_valid_roles


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear all module-level caches between tests so env-var mutations take effect."""
    get_auth_settings.cache_clear()
    get_valid_roles.cache_clear()
    yield
    get_auth_settings.cache_clear()
    get_valid_roles.cache_clear()


@pytest.fixture()
def non_local_env(monkeypatch):
    """Override ENVIRONMENT to 'staging' so local-dev short-circuits are bypassed."""
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("AZURE_AD_TENANT_ID", "test-tenant-id")
    monkeypatch.setenv("AZURE_AD_CLIENT_ID", "test-client-id")
