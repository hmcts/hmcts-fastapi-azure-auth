"""Tests for hmcts_azure_auth.utils."""

from hmcts_azure_auth.utils import emails_match, sanitize_for_log


class TestEmailsMatch:
    def test_identical_lowercase(self):
        assert emails_match("user@example.com", "user@example.com") is True

    def test_case_insensitive(self):
        assert emails_match("User@Example.COM", "user@example.com") is True

    def test_whitespace_stripped(self):
        assert emails_match("  user@example.com  ", "user@example.com") is True

    def test_different_emails(self):
        assert emails_match("a@example.com", "b@example.com") is False

    def test_none_left(self):
        assert emails_match(None, "user@example.com") is False

    def test_none_right(self):
        assert emails_match("user@example.com", None) is False

    def test_both_none(self):
        assert emails_match(None, None) is False

    def test_empty_string(self):
        assert emails_match("", "user@example.com") is False

    def test_whitespace_only(self):
        assert emails_match("   ", "user@example.com") is False


class TestSanitizeForLog:
    def test_passthrough_normal_string(self):
        assert sanitize_for_log("hello world") == "hello world"

    def test_strips_newline(self):
        assert sanitize_for_log("line1\nline2") == "line1\\nline2"

    def test_strips_carriage_return(self):
        assert sanitize_for_log("line1\rline2") == "line1\\rline2"

    def test_strips_crlf(self):
        assert sanitize_for_log("line1\r\nline2") == "line1\\r\\nline2"

    def test_converts_non_string(self):
        assert sanitize_for_log(42) == "42"

    def test_none_becomes_string(self):
        assert sanitize_for_log(None) == "None"
