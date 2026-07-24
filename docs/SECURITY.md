# Security Policy

## Supported Versions

This project follows [semantic versioning](https://semver.org/). Security fixes are made
against the latest released minor version on the `main` branch; older versions are not
patched separately.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities via **GitHub private vulnerability reporting**: open a
report from the "Security" tab of this repository → "Report a vulnerability". This
creates a private advisory visible only to maintainers until a fix is published.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal reproduction is ideal)
- The affected version(s) of `hmcts-fastapi-azure-auth`

We aim to acknowledge reports within 5 working days and to keep you informed of
remediation progress. Please allow us a reasonable period to investigate and release a
fix before any public disclosure.

## Scope Notes

This library integrates with Azure App Service Easy Auth and Azure AD JWT verification.
See the [Security](../README.md#security) section of the README for architectural trust
assumptions (in particular, that `X-Ms-Client-Principal` is only trustworthy when the
consuming application is reachable exclusively via the Easy Auth front door) — reports
that rely on bypassing that documented deployment requirement are still welcome, but
please note the assumption in your report.
