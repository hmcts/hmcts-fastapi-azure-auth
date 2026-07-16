"""Core Pydantic models and settings for hmcts-fastapi-azure-auth."""

from __future__ import annotations

from functools import cache

from pydantic import BaseModel
from pydantic_settings import BaseSettings


class AuthUser(BaseModel):
    """Authenticated user as returned by the library's built-in dependency.

    For apps that need their own DB-backed user model, use build_current_user_dep()
    to extend this with a user_resolver.
    """

    user_id: str
    name: str
    email: str
    roles: list[str] = []


class AuthenticatedIdentity(BaseModel):
    """Raw identity extracted from the Azure Easy Auth header before JWT cross-check."""

    azure_user_id: str
    email: str
    name: str = ""


class AuthSettings(BaseSettings):
    """Base settings class for Azure AD authentication.

    Consuming apps should subclass this and add their own fields:

        class Settings(AuthSettings):
            MY_APP_SETTING: str

    All fields are read from environment variables with the same names.
    AZURE_AD_CLIENT_ID and AZURE_AD_TENANT_ID default to "" so the library
    can be imported in test environments — JWT verification will be
    non-functional unless both are set or JWT_ENABLE_VERIFICATION=False.
    """

    AZURE_AD_CLIENT_ID: str = ""
    AZURE_AD_TENANT_ID: str = ""
    JWT_ENABLE_VERIFICATION: bool = True
    JWT_VERIFICATION_STRICT: bool = True
    AUTH_APPROLES: str | None = None


@cache
def get_auth_settings() -> AuthSettings:
    """Return the cached library-level auth settings singleton.

    In tests, call get_auth_settings.cache_clear() between test cases
    when you need different env-var values to take effect.
    """
    return AuthSettings()
