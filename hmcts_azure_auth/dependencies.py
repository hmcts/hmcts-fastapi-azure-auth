"""FastAPI dependencies for Azure AD authentication and RBAC enforcement."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request

from hmcts_azure_auth.audit import AuditEvent, AuditEventType, AuditWriter
from hmcts_azure_auth.easy_auth import parse_easy_auth_header
from hmcts_azure_auth.jwt import get_jwt_service
from hmcts_azure_auth.models import AuthUser
from hmcts_azure_auth.roles import get_valid_roles
from hmcts_azure_auth.utils import emails_match, sanitize_for_log

logger = logging.getLogger(__name__)

# Local development identity — used when ENVIRONMENT == "local".
_LOCAL_DEV_USER_ID = "local-dev-user-123"
_LOCAL_DEV_NAME = "Local Developer"
_LOCAL_DEV_EMAIL = "developer@localhost.com"


def _is_local_dev() -> bool:
    return os.getenv("ENVIRONMENT", "production").lower() == "local"


def _local_dev_roles() -> list[str]:
    """All configured roles — local dev gets full access by default."""
    return list(get_valid_roles().values())


async def get_current_user_base(
    x_ms_client_principal: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> AuthUser:
    """Built-in FastAPI dependency — returns AuthUser with no DB involvement.

    Suitable for apps that only need identity and roles.
    For apps that need a DB-backed user object, use build_current_user_dep().

    Authentication flow:
    1. Short-circuits to mock identity in local development (ENVIRONMENT=local).
    2. Parses X-Ms-Client-Principal (Azure Easy Auth) for primary identity.
    3. Verifies the Bearer JWT and uses it as the authoritative source of roles
       and (if present) as a cross-check on the Easy Auth identity.
    """
    if _is_local_dev():
        logger.info("Local dev mode — using mock identity")
        return AuthUser(
            user_id=_LOCAL_DEV_USER_ID,
            name=_LOCAL_DEV_NAME,
            email=_LOCAL_DEV_EMAIL,
            roles=_local_dev_roles(),
        )

    if not x_ms_client_principal:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Ensure Azure Easy Auth is configured.",
        )

    identity = parse_easy_auth_header(x_ms_client_principal)
    azure_user_id = identity.azure_user_id
    email = identity.email
    roles: list[str] = []

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            decoded = await get_jwt_service().verify_jwt_token(token)
            if decoded:
                jwt_info = get_jwt_service().extract_user_info_from_jwt(decoded)
                jwt_oid: str = jwt_info["azure_user_id"]
                jwt_email: str = jwt_info["email"]
                roles = jwt_info["roles"]

                # Identity cross-check: Easy Auth oid must match JWT oid.
                if jwt_oid and azure_user_id and jwt_oid.lower() != azure_user_id.lower():
                    logger.error(
                        "Identity mismatch — potential spoofing: easy_auth_oid=%s jwt_oid=%s",
                        sanitize_for_log(azure_user_id),
                        sanitize_for_log(jwt_oid),
                    )
                    if get_jwt_service().strict_mode:
                        raise HTTPException(
                            status_code=401,
                            detail="Authentication claims mismatch between Easy Auth and JWT",
                        )

                if jwt_email and not emails_match(email, jwt_email):
                    # Note the mismatch without logging the actual email addresses —
                    # oid is cryptographically verified and non-PII.
                    logger.info(
                        "Email differs between Easy Auth and JWT (identity verified) for user oid=%s",
                        sanitize_for_log(jwt_oid or azure_user_id),
                    )

                # Prefer the JWT oid as it is cryptographically verified.
                if jwt_oid:
                    azure_user_id = jwt_oid

                logger.info("JWT verification passed")

        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("JWT verification error: %s", exc)
            if get_jwt_service().strict_mode:
                raise

    elif get_jwt_service().strict_mode:
        raise HTTPException(status_code=401, detail="JWT token required in strict verification mode")

    logger.info(
        "Authentication validated — id=%s roles=%s",
        sanitize_for_log(azure_user_id),
        [sanitize_for_log(r) for r in roles],
    )
    return AuthUser(
        user_id=azure_user_id,
        name=identity.name,
        email=email,
        roles=roles,
    )


def build_current_user_dep(
    user_resolver: Callable[[str, str, list[str]], Any],
) -> Callable:
    """Factory that creates a FastAPI dependency returning an app-defined user type.

    user_resolver is called with (azure_user_id, email, roles) after the library
    completes authentication. It should return whatever user object your application
    needs (e.g. a SQLModel User with DB-fetched fields).

    The resolver may be sync or async. It is responsible for opening its own
    DB session if needed.

    Example:

        def _resolve_user(azure_user_id: str, email: str, roles: list[str]) -> User:
            with Session(get_engine()) as session:
                user = session.exec(
                    select(User).where(User.azure_user_id == azure_user_id)
                ).first()
                if not user:
                    user = User(email=email, azure_user_id=azure_user_id)
                    session.add(user)
                    session.commit()
                    session.refresh(user)
                user.__dict__["app_roles"] = roles
                return user

        get_current_user = build_current_user_dep(_resolve_user)
    """

    async def _dep(
        auth_user: AuthUser = Depends(get_current_user_base),  # noqa: B008
    ) -> Any:
        if asyncio.iscoroutinefunction(user_resolver):
            return await user_resolver(auth_user.user_id, auth_user.email, auth_user.roles)
        return user_resolver(auth_user.user_id, auth_user.email, auth_user.roles)

    return _dep


def get_allowlisted_user(
    required_roles_all: list[str] | None = None,
    required_roles_any: list[str] | None = None,
    audit_writer: AuditWriter | None = None,
    current_user_dep: Callable | None = None,
    get_roles: Callable[[Any], list[str]] = lambda u: (
        u.roles if isinstance(u, AuthUser) else u.__dict__.get("app_roles", [])
    ),
) -> Callable:
    """Factory returning a FastAPI dependency that enforces role requirements.

    With no role arguments, any authenticated user is allowed through.
    required_roles_all: user must hold every listed role.
    required_roles_any: user must hold at least one of the listed roles.
    Both may be combined — all conditions must pass.
    audit_writer: optional sync or async callable called with an AuditEvent on 403.
    current_user_dep: which user dependency to resolve; defaults to get_current_user_base.
      Pass your app's get_current_user (built with build_current_user_dep) to get your
      full DB user object back from this dependency.
    get_roles: how to extract roles from the resolved user object; defaults to handling
      both AuthUser (roles attribute) and app DB users (app_roles in __dict__).

    Consuming apps will typically create a thin wrapper so all route files use
    a consistent local import:

        # In your app's utils/dependencies.py:
        from hmcts_azure_auth.dependencies import get_allowlisted_user as _lib_allowlist

        def get_allowlisted_user(required_roles_all=None, required_roles_any=None, audit_writer=None):
            return _lib_allowlist(
                required_roles_all=required_roles_all,
                required_roles_any=required_roles_any,
                audit_writer=audit_writer,
                current_user_dep=get_current_user,  # your DB-backed dep
            )
    """
    _user_dep = current_user_dep or get_current_user_base

    async def _check(
        request: Request,
        current_user: Any = Depends(_user_dep),  # noqa: B008
    ) -> Any:
        if _is_local_dev():
            return current_user

        roles: list[str] = get_roles(current_user)
        resource = f"{request.method} {request.url.path}"
        safe_roles = [sanitize_for_log(r) for r in roles]

        async def _maybe_write_audit(required: list[str]) -> None:
            if not audit_writer:
                return
            forwarded_for = request.headers.get("X-Forwarded-For")
            client_ip: str | None = (
                forwarded_for.split(",")[0].strip()
                if forwarded_for
                else (request.client.host if request.client else None)
            )
            event = AuditEvent(
                event_type=AuditEventType.ACCESS_DENIED,
                user_id=sanitize_for_log(
                    current_user.user_id
                    if isinstance(current_user, AuthUser)
                    else getattr(current_user, "azure_user_id", "unknown")
                ),
                email=sanitize_for_log(current_user.email if hasattr(current_user, "email") else "unknown"),
                held_roles=safe_roles,
                required_roles=[sanitize_for_log(r) for r in required],
                resource=sanitize_for_log(resource),
                client_ip=client_ip,
            )
            if asyncio.iscoroutinefunction(audit_writer):
                await audit_writer(event)
            else:
                await asyncio.to_thread(audit_writer, event)

        for role in required_roles_all or []:
            if role not in roles:
                logger.warning(
                    "UNAUTHORISED_ACCESS_ATTEMPT user_id=%s email=%s held_roles=%s required_roles=%s resource=%s",
                    sanitize_for_log(
                        current_user.user_id
                        if isinstance(current_user, AuthUser)
                        else getattr(current_user, "id", "unknown")
                    ),
                    sanitize_for_log(getattr(current_user, "email", "unknown")),
                    safe_roles,
                    [sanitize_for_log(role)],
                    sanitize_for_log(resource),
                )
                await _maybe_write_audit([role])
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied. You must have the '{role}' role to access this resource.",
                )

        if required_roles_any and not any(r in roles for r in required_roles_any):
            logger.warning(
                "UNAUTHORISED_ACCESS_ATTEMPT user_id=%s email=%s held_roles=%s required_roles=%s resource=%s",
                sanitize_for_log(
                    current_user.user_id
                    if isinstance(current_user, AuthUser)
                    else getattr(current_user, "id", "unknown")
                ),
                sanitize_for_log(getattr(current_user, "email", "unknown")),
                safe_roles,
                [sanitize_for_log(r) for r in required_roles_any],
                sanitize_for_log(resource),
            )
            await _maybe_write_audit(required_roles_any)
            raise HTTPException(
                status_code=403,
                detail=(f"Access denied. You must have one of the following roles: {', '.join(required_roles_any)}."),
            )

        logger.info(
            "Role check passed for user_id=%s (roles=%s)",
            sanitize_for_log(
                current_user.user_id
                if isinstance(current_user, AuthUser)
                else getattr(current_user, "azure_user_id", "unknown")
            ),
            safe_roles,
        )
        return current_user

    return _check
