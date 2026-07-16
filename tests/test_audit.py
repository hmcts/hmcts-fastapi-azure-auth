"""Tests for hmcts_azure_auth.audit."""

from datetime import UTC, datetime

import pytest

from hmcts_azure_auth.audit import AuditEvent, AuditEventType


class TestAuditEventType:
    def test_access_denied_value(self):
        assert AuditEventType.ACCESS_DENIED == "ACCESS_DENIED"

    def test_role_change_value(self):
        assert AuditEventType.ROLE_CHANGE == "ROLE_CHANGE"

    def test_is_string_subclass(self):
        assert isinstance(AuditEventType.ACCESS_DENIED, str)


class TestAuditEvent:
    def test_required_fields(self):
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            user_id="user-123",
            email="user@example.com",
        )
        assert event.event_type == "ACCESS_DENIED"
        assert event.user_id == "user-123"
        assert event.email == "user@example.com"

    def test_defaults(self):
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            user_id="user-123",
            email="user@example.com",
        )
        assert event.held_roles == []
        assert event.required_roles == []
        assert event.resource is None
        assert event.detail is None

    def test_timestamp_defaults_to_utc_now(self):
        before = datetime.now(UTC)
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            user_id="u",
            email="e@example.com",
        )
        after = datetime.now(UTC)
        assert before <= event.timestamp <= after

    def test_accepts_custom_string_event_type(self):
        event = AuditEvent(
            event_type="TRANSCRIPT_VIEWED",
            user_id="u",
            email="e@example.com",
        )
        assert event.event_type == "TRANSCRIPT_VIEWED"

    def test_full_fields(self):
        event = AuditEvent(
            event_type=AuditEventType.ROLE_CHANGE,
            user_id="user-123",
            email="admin@example.com",
            held_roles=["SystemAdministrator"],
            required_roles=["SystemAdministrator"],
            resource="PUT /admin/users/42/role",
            detail={"old_role": "Normal", "new_role": "Judge"},
        )
        assert event.held_roles == ["SystemAdministrator"]
        assert event.detail["new_role"] == "Judge"
