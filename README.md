# hmcts-fastapi-azure-auth

FastAPI Azure AD authentication and RBAC library for HMCTS applications.

Provides Azure Easy Auth header parsing, RS256 JWT verification against Azure AD v2.0, role-based access control via Azure AD App Roles, and a structured audit event contract — all decoupled from any specific application's database layer.

## Features

- **Easy Auth integration** — decodes and validates `X-Ms-Client-Principal` headers from Azure App Service
- **JWT verification** — RS256 signature verification via PyJWKClient against the Azure AD v2.0 JWKS endpoint
- **RBAC enforcement** — `get_allowlisted_user()` factory supporting `required_roles_all` / `required_roles_any` guards
- **App role management** — configurable via `AUTH_APPROLES` environment variable; ships with `Judge`, `LegalTextManager`, `SystemAdministrator`, `Normal` defaults
- **Audit events** — `AuditEvent` / `AuditEventType` contract; `ACCESS_DENIED` events emitted automatically; app writes them to DB via a callback
- **DB-agnostic** — `build_current_user_dep(user_resolver)` factory lets each app wire its own user model

## Installation

```bash
pip install hmcts-fastapi-azure-auth
```

## Quick start

```python
from hmcts_azure_auth import AuthSettings, build_current_user_dep, get_allowlisted_user, get_role

class Settings(AuthSettings):
    MY_EXTRA_SETTING: str = "default"

def _resolve_user(azure_user_id: str, email: str, roles: list[str]):
    # DB lookup / create — return whatever user object your app needs
    ...

get_current_user = build_current_user_dep(_resolve_user)

def get_allowlisted_user_app(required_roles_all=None, required_roles_any=None, audit_writer=None):
    from hmcts_azure_auth import get_allowlisted_user as _lib
    return _lib(
        required_roles_all=required_roles_all,
        required_roles_any=required_roles_any,
        audit_writer=audit_writer,
        current_user_dep=get_current_user,
    )

@router.get("/documents")
async def list_documents(user=Depends(get_allowlisted_user_app(required_roles_any=[get_role("Judge")]))):
    ...
```

## Required environment variables

| Variable | Description |
|---|---|
| `AZURE_AD_CLIENT_ID` | Azure AD application (client) ID |
| `AZURE_AD_TENANT_ID` | Azure AD tenant ID |
| `JWT_ENABLE_VERIFICATION` | Enable JWT signature verification (default: `true`) |
| `JWT_VERIFICATION_STRICT` | Treat verification failures as 401 (default: `true`) |
| `AUTH_APPROLES` | JSON dict overriding default app roles (optional) |
