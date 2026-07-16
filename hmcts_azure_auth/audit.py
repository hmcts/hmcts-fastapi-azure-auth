"""Audit event contract for auth-related security events.

The library emits ACCESS_DENIED events internally via get_allowlisted_user().
Consuming apps emit ROLE_CHANGE (and any app-specific events) themselves.

Usage in a consuming app:

    from hmcts_azure_auth.audit import AuditEvent, AuditEventType, AuditWriter

    def write_audit_event(event: AuditEvent) -> None:
        with Session(get_engine()) as session:
            session.add(AuditLog(
                event_type=event.event_type,
                user_id=event.user_id,
                email=event.email,
                held_roles=event.held_roles,
                required_roles=event.required_roles,
                resource=event.resource,
                detail=event.detail,
                timestamp=event.timestamp,
            ))
            session.commit()

    # Wire into get_allowlisted_user:
    Depends(get_allowlisted_user(
        required_roles_any=[get_role("Judge")],
        audit_writer=write_audit_event,
    ))
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Callable

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    """Standard audit event types produced by the auth library.

    Apps may use their own additional string values alongside these.
    """

    ACCESS_DENIED = "ACCESS_DENIED"
    ROLE_CHANGE = "ROLE_CHANGE"


class AuditEvent(BaseModel):
    """Structured audit record emitted by library hooks and consuming apps.

    event_type accepts AuditEventType members or any custom string so apps
    can extend the set of events without subclassing.
    """

    event_type: str
    user_id: str
    email: str
    held_roles: list[str] = []
    required_roles: list[str] = []
    resource: str | None = None
    detail: dict | None = None
    client_ip: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# Type alias: sync callable that receives a structured audit event.
# Async callables are also accepted by get_allowlisted_user().
AuditWriter = Callable[[AuditEvent], None]
