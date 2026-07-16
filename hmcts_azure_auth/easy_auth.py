"""Azure App Service Easy Auth header parsing."""

from __future__ import annotations

import base64
import json
import logging

from fastapi import HTTPException

from hmcts_azure_auth.models import AuthenticatedIdentity

logger = logging.getLogger(__name__)

# Claim types used to locate the user's email address, in priority order.
_EMAIL_CLAIM_TYPES = ("email", "preferred_username", "upn")


def parse_easy_auth_header(x_ms_client_principal: str) -> AuthenticatedIdentity:
    """Decode and parse the X-Ms-Client-Principal header injected by Azure App Service.

    Raises HTTPException 401 if the header is missing required fields or is malformed.
    """
    try:
        decoded = base64.b64decode(x_ms_client_principal).decode("utf-8")
        payload = json.loads(decoded)
    except (json.JSONDecodeError, base64.binascii.Error) as exc:
        logger.debug("Easy Auth header parse failure: %s", exc)
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication header",
        ) from exc

    azure_user_id: str = payload.get("userId", "")
    claims: list[dict] = payload.get("claims", [])

    email = _extract_claim(claims, _EMAIL_CLAIM_TYPES)
    if not email:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: email claim missing from Easy Auth header",
        )

    name = _extract_claim(claims, ("name",)) or ""

    logger.debug("Easy Auth identity resolved: user_id=%s email=%s", azure_user_id, email)
    return AuthenticatedIdentity(azure_user_id=azure_user_id, email=email, name=name)


def _extract_claim(claims: list[dict], typ_values: tuple[str, ...]) -> str | None:
    """Return the first non-empty claim value matching any of the given typ names."""
    for typ in typ_values:
        for claim in claims:
            if claim.get("typ") == typ:
                val = claim.get("val", "").strip()
                if val:
                    return val
    return None
