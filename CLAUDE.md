# CLAUDE.md

Guidance for Claude Code (and contributors) working in **hmcts-fastapi-azure-auth** —
a FastAPI Azure AD authentication + RBAC **library** consumed by HMCTS applications.

## This is public, security-critical code

This repository is **public**, and it is an **authentication library**: a flaw here
is inherited by every application that depends on it, and the code + full git history
are world-readable. Hold a higher bar than for an ordinary app.

**Never commit:** secrets/credentials, real Azure tenant/client/subscription/object
IDs, real tokens or private keys, internal hostnames, or real person data. Use
placeholders and env-sourced config. (History is currently clean — keep it that way.)

## Auth invariants — do NOT regress these

These are the security properties the library exists to provide. A change that
weakens any of them must be rejected:

- **JWT algorithm is pinned to `RS256`.** Never accept `alg=none` or allow the
  algorithm to be taken from the token. Always verify **signature + audience +
  issuer + exp/nbf/iat** (see `hmcts_azure_auth/jwt.py`).
- **Fail closed by default.** `JWT_ENABLE_VERIFICATION` and `JWT_VERIFICATION_STRICT`
  default to `True`; the `ENVIRONMENT` local-dev bypass defaults to `production`.
  Never flip a default to the permissive value to make something pass — fix the
  caller/test instead. (The stale-test-assuming-`local` trap is a real one: set
  `ENVIRONMENT=local` in the *test*, never lower the product default.)
- **`X-Ms-Client-Principal` is untrusted input.** `parse_easy_auth_header` cannot
  verify the header's authenticity — it trusts Azure App Service to have injected
  it at the edge. Consuming apps MUST be reachable only via the Easy Auth front
  door; document this, never weaken it.
- **Never log secrets or PII.** No tokens, and no `email`/`upn`/`preferred_username`
  in logs (use the non-PII `oid`). Applies at every level except deliberate
  security-audit WARNINGs.

## Dev workflow

- Managed with **uv**. Install: `uv sync --extra dev`.
- **Verify before claiming done** (run and read the output):
  ```bash
  uv run pytest -q
  uv run ruff check .
  uv run ruff format --check .
  uv build            # packaging must stay valid (published to PyPI)
  ```
- `ruff` is blocking; `pyright` is advisory for now.

## Testing

Behavioural code ships with a test that turns red if it regresses — the bar is
high for an auth library. Prefer exercising the real code path; when mocking an
external boundary (JWKS, Azure), assert on the outcome, not just that a mock was
called. New security behaviour (a claim check, a fail-closed path) must have a
test that fails if the check is removed.

## Pre-commit

`pre-commit` runs ruff, hygiene hooks, and **gitleaks** (secret scanning) — the
first line of defence for a public repo. Install once: `pre-commit install`
(a Claude Code `SessionStart` hook in `.claude/settings.json` does this
automatically). Requires `gitleaks` on `PATH`.
