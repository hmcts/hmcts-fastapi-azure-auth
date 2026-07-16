"""hmcts-fastapi-azure-auth — Azure AD authentication and RBAC for HMCTS FastAPI applications.

Quick-start
-----------
1. Subclass AuthSettings in your app's settings module:

    from hmcts_azure_auth import AuthSettings

    class Settings(AuthSettings):
        MY_APP_SETTING: str = "default"

2. Create your user dependency:

    from hmcts_azure_auth import build_current_user_dep, get_role
    from app.database.postgres_models import User
    from sqlmodel import Session, select

    def _resolve_user(azure_user_id: str, email: str, roles: list[str]) -> User:
        with Session(get_engine()) as session:
            user = session.exec(select(User).where(User.azure_user_id == azure_user_id)).first()
            if not user:
                user = User(email=email, azure_user_id=azure_user_id)
                session.add(user); session.commit(); session.refresh(user)
            user.__dict__["app_roles"] = roles
            return user

    get_current_user = build_current_user_dep(_resolve_user)

3. Wrap get_allowlisted_user so routes use a single local import:

    from hmcts_azure_auth import get_allowlisted_user as _lib_allowlist

    def get_allowlisted_user(required_roles_all=None, required_roles_any=None, audit_writer=None):
        return _lib_allowlist(
            required_roles_all=required_roles_all,
            required_roles_any=required_roles_any,
            audit_writer=audit_writer,
            current_user_dep=get_current_user,
        )

4. Protect an endpoint:

    @router.get("/documents")
    async def list_documents(user = Depends(get_allowlisted_user(required_roles_any=[get_role("Judge")]))):
        ...
"""

from hmcts_azure_auth.audit import AuditEvent, AuditEventType, AuditWriter
from hmcts_azure_auth.dependencies import (
    build_current_user_dep,
    get_allowlisted_user,
    get_current_user_base,
)
from hmcts_azure_auth.easy_auth import parse_easy_auth_header
from hmcts_azure_auth.jwt import JWTVerificationService, jwt_verification_service
from hmcts_azure_auth.models import (
    AuthenticatedIdentity,
    AuthSettings,
    AuthUser,
    get_auth_settings,
)
from hmcts_azure_auth.roles import (
    DEFAULT_APP_ROLES,
    get_role,
    get_valid_roles,
    has_any_role,
)
from hmcts_azure_auth.utils import emails_match, sanitize_for_log

__version__ = "0.1.0"

__all__ = [
    # Audit
    "AuditEvent",
    "AuditEventType",
    "AuditWriter",
    # Dependencies
    "build_current_user_dep",
    "get_allowlisted_user",
    "get_current_user_base",
    # Easy Auth
    "parse_easy_auth_header",
    # JWT
    "JWTVerificationService",
    "jwt_verification_service",
    # Models / Settings
    "AuthenticatedIdentity",
    "AuthSettings",
    "AuthUser",
    "get_auth_settings",
    # Roles
    "DEFAULT_APP_ROLES",
    "get_role",
    "get_valid_roles",
    "has_any_role",
    # Utils
    "emails_match",
    "sanitize_for_log",
]
