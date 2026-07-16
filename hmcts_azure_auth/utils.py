"""Shared utility functions used across auth and RBAC logic."""

from __future__ import annotations


def sanitize_for_log(value: object) -> str:
    """Remove newline control characters to prevent log injection."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


def emails_match(email1: str | None, email2: str | None) -> bool:
    """Case-insensitive email comparison per RFC 5321.

    Different Azure systems (Easy Auth vs JWT) can return the same address
    with different casing; this normalises before comparing.
    Returns False if either value is None or empty after stripping.
    """
    if not email1 or not email2:
        return False
    e1 = email1.strip().lower()
    e2 = email2.strip().lower()
    return bool(e1 and e2 and e1 == e2)
