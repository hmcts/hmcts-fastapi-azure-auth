"""Azure AD JWT verification via RS256 + JWKS."""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any

import jwt
from fastapi import HTTPException
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


class JWTVerificationService:
    """Verifies Azure AD v2.0 access tokens and extracts identity claims.

    Initialises lazily from AuthSettings — JWKS client is only created when
    AZURE_AD_TENANT_ID is non-empty and JWT_ENABLE_VERIFICATION is True.
    """

    def __init__(self) -> None:
        from hmcts_azure_auth.models import get_auth_settings

        settings = get_auth_settings()
        self.tenant_id: str = settings.AZURE_AD_TENANT_ID
        self.client_id: str = settings.AZURE_AD_CLIENT_ID
        self.enabled: bool = settings.JWT_ENABLE_VERIFICATION
        self.strict_mode: bool = settings.JWT_VERIFICATION_STRICT
        self.jwks_client: PyJWKClient | None = None

        if self.enabled and self.tenant_id:
            jwks_url = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
            self.jwks_client = PyJWKClient(
                jwks_url,
                cache_keys=True,
                max_cached_keys=16,
            )
            logger.info("JWT verification service initialised — strict_mode=%s", self.strict_mode)

    async def verify_jwt_token(self, token: str) -> dict[str, Any] | None:  # noqa: C901, PLR0911, PLR0912
        """Verify token signature and standard claims.

        Returns the decoded payload on success.
        Returns None when verification is disabled or non-strict mode ignores errors.
        Raises HTTPException 401 in strict mode on any failure.
        """
        if not self.enabled:
            return None

        if not token:
            if self.strict_mode:
                raise HTTPException(status_code=401, detail="JWT token required")
            return None

        if not self.jwks_client:
            # Enabled but no tenant configured — misconfiguration.
            if self.strict_mode:
                raise HTTPException(
                    status_code=500,
                    detail="JWT verification is enabled but AZURE_AD_TENANT_ID is not configured",
                )
            return None

        try:
            loop = asyncio.get_running_loop()
            signing_key = await loop.run_in_executor(None, self.jwks_client.get_signing_key_from_jwt, token)
            _client_id = self.client_id
            _tenant_id = self.tenant_id
            decoded = await loop.run_in_executor(
                None,
                lambda: jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    audience=_client_id,
                    issuer=f"https://login.microsoftonline.com/{_tenant_id}/v2.0",
                    options={
                        "verify_signature": True,
                        "verify_aud": True,
                        "verify_iss": True,
                        "verify_exp": True,
                        "verify_nbf": True,
                        "verify_iat": True,
                    },
                ),
            )
        except jwt.ExpiredSignatureError as exc:
            logger.warning("JWT token has expired")
            if self.strict_mode:
                raise HTTPException(status_code=401, detail="JWT token has expired") from exc
            return None
        except jwt.InvalidAudienceError as exc:
            logger.warning("JWT token audience mismatch")
            if self.strict_mode:
                raise HTTPException(status_code=401, detail="JWT token audience invalid") from exc
            return None
        except jwt.InvalidIssuerError as exc:
            logger.warning("JWT token issuer invalid")
            if self.strict_mode:
                raise HTTPException(status_code=401, detail="JWT token issuer invalid") from exc
            return None
        except jwt.InvalidTokenError as exc:
            logger.warning("JWT token verification failed: %s", exc)
            if self.strict_mode:
                raise HTTPException(status_code=401, detail=f"JWT token invalid: {exc!s}") from exc
            return None
        except Exception as exc:
            logger.exception("Unexpected error during JWT verification")
            if self.strict_mode:
                raise HTTPException(status_code=401, detail="JWT verification failed") from exc
            return None
        else:
            # Log the non-PII Azure AD object id (oid), never the email/UPN —
            # this log is emitted at INFO and must not leak user PII.
            logger.info(
                "JWT verification passed for user oid=%s",
                decoded.get("oid", "unknown"),
            )
            return decoded

    def extract_user_info_from_jwt(self, decoded_token: dict[str, Any]) -> dict[str, Any]:
        """Extract identity and role claims from a verified JWT payload."""
        roles = decoded_token.get("roles", [])
        return {
            "email": decoded_token.get("email") or decoded_token.get("preferred_username", ""),
            "name": decoded_token.get("name", ""),
            "azure_user_id": decoded_token.get("oid", ""),
            "upn": decoded_token.get("upn", ""),
            "roles": roles if isinstance(roles, list) else [],
        }


@functools.cache
def get_jwt_service() -> JWTVerificationService:
    """Return the process-wide JWTVerificationService, created on first call.

    Lazy initialisation ensures environment variables are read after injection
    (e.g. in test fixtures or serverless cold-start scenarios) rather than at
    module import time.
    """
    return JWTVerificationService()
