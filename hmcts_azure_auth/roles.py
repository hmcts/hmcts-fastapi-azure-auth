"""Azure AD application role definitions and validation."""

from __future__ import annotations

import json
import logging
from functools import cache

logger = logging.getLogger(__name__)

DEFAULT_APP_ROLES: dict[str, str] = {
    "Judge": "Judge",
    "LegalTextManager": "LegalTextManager",
    "SystemAdministrator": "SystemAdministrator",
    "Normal": "Normal",
}


@cache
def get_valid_roles() -> dict[str, str]:
    """Return the effective set of valid app role values.

    Reads AUTH_APPROLES from settings as a JSON dict to override the defaults.
    The override must include all DEFAULT_APP_ROLES keys; extra keys are allowed.
    Falls back to DEFAULT_APP_ROLES on any parse or validation error.

    Result is cached for the process lifetime. Call get_valid_roles.cache_clear()
    in tests when you need different AUTH_APPROLES values to take effect.
    """
    from hmcts_azure_auth.models import get_auth_settings

    settings = get_auth_settings()
    if not settings.AUTH_APPROLES:
        return DEFAULT_APP_ROLES

    try:
        roles = json.loads(settings.AUTH_APPROLES)
    except json.JSONDecodeError:
        logger.exception("AUTH_APPROLES is not valid JSON, using defaults. Example: %s", DEFAULT_APP_ROLES)
        return DEFAULT_APP_ROLES

    if not isinstance(roles, dict):
        logger.error("AUTH_APPROLES must be a JSON object, using defaults. Example: %s", DEFAULT_APP_ROLES)
        return DEFAULT_APP_ROLES

    missing = [k for k in DEFAULT_APP_ROLES if k not in roles]
    if missing:
        logger.error(
            "AUTH_APPROLES is missing required keys %s, using defaults. Example: %s",
            missing,
            DEFAULT_APP_ROLES,
        )
        return DEFAULT_APP_ROLES

    if not all(isinstance(v, str) for v in roles.values()):
        logger.error("AUTH_APPROLES values must all be strings, using defaults. Example: %s", DEFAULT_APP_ROLES)
        return DEFAULT_APP_ROLES

    logger.info("Using custom app roles from AUTH_APPROLES: %s", roles)
    return roles


def has_any_role(user_roles: list[str]) -> bool:
    """Return True if the user holds at least one valid app role."""
    return bool(set(user_roles) & set(get_valid_roles().values()))


def get_role(role_name: str) -> str | None:
    """Return the role value string for a given role name, or None if unknown."""
    return get_valid_roles().get(role_name)
