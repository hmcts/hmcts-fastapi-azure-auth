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
async def list_documents(user=Depends(get_allowlisted_user_app(required_roles_any=[get_role("Judge")]))): ...
```

## Required environment variables

| Variable | Description |
|---|---|
| `AZURE_AD_CLIENT_ID` | Azure AD application (client) ID |
| `AZURE_AD_TENANT_ID` | Azure AD tenant ID |
| `JWT_ENABLE_VERIFICATION` | Enable JWT signature verification (default: `true`) |
| `JWT_VERIFICATION_STRICT` | Treat verification failures as 401 (default: `true`) |
| `AUTH_APPROLES` | JSON dict overriding default app roles (optional) |

## Security

### Easy Auth header trust — deployment requirement

`parse_easy_auth_header()` decodes and trusts the `X-Ms-Client-Principal` header that
**Azure App Service Easy Auth** injects after authenticating a request — the library has
no way to independently verify that this header was actually set by Easy Auth rather
than by the caller.

**The consuming application MUST be reachable only via the Easy Auth front door.** If the
app is directly reachable — e.g. its origin is exposed without going through Easy Auth,
or an internal network path bypasses it — a caller can forge an `X-Ms-Client-Principal`
header to **impersonate any user and any set of roles**. This is not a bug in the
library; it is an inherent property of how Easy Auth works, and it is the deploying
application's responsibility to ensure Easy Auth cannot be bypassed (e.g. via network
restrictions, access restrictions on the App Service, or a WAF/front door that strips
client-supplied `X-Ms-*` headers before Easy Auth re-adds them).

### JWT verification settings

Keep `JWT_ENABLE_VERIFICATION=true` and `JWT_VERIFICATION_STRICT=true` in every deployed
environment — these are the safe defaults and should not be overridden in production.

- `JWT_VERIFICATION_STRICT=false` is intended for **local/dev only**: on an invalid or
  expired token it returns `None` (falling back to Easy Auth-only identity) instead of
  raising a 401. Running with non-strict verification in a deployed environment weakens
  the identity/role cross-check between Easy Auth and the JWT.

### Local development bypass

When `ENVIRONMENT=local`, `get_current_user_base()` short-circuits authentication
entirely and returns a mock identity holding **every configured app role**. This is
opt-in — the default (when `ENVIRONMENT` is unset) is `"production"`, which does not
trigger the bypass — but it is critical that **`ENVIRONMENT=local` is never set in any
deployed environment**, since doing so disables authentication and RBAC completely.

## Development

This repo uses [uv](https://docs.astral.sh/uv/) and enforces linting, formatting, and
secret scanning via [pre-commit](https://pre-commit.com/).

```bash
# Install dependencies, including dev tools (ruff, pyright)
uv sync --extra dev

# Install the git hooks (run once per clone).
# Requires `gitleaks` on your PATH (e.g. `brew install gitleaks`).
pre-commit install
```

The hooks run on every commit — **ruff** (lint + format), basic file hygiene, and
**gitleaks** (secret scanning; this is a public repo). Run them across the whole tree
at any time with `pre-commit run --all-files`.

Before pushing, verify locally (this mirrors CI):

```bash
uv run pytest                  # tests
uv run ruff check .            # lint (blocking)
uv run ruff format --check .   # formatting (blocking)
uv build                       # packaging must stay valid
```

Behavioural changes ship with a test. For security-critical code (JWT verification,
RBAC) prefer exercising the real path over mocks — see `tests/test_jwt.py` for the
pattern (a real RS256 keypair signs real tokens; only the external JWKS fetch is
stubbed, so signature/algorithm-pinning/audience/issuer/expiry are all verified for
real). See `CLAUDE.md` for the full contributor invariants.
