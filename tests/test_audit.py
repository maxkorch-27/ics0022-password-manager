"""JSONL event format, sensitive-data exclusion, event codes, permissions."""
import json
import logging
import os
from datetime import datetime

import pytest
from src import audit


def read_events():
    for handler in logging.getLogger("password_manager.audit").handlers:
        handler.flush()
    return [json.loads(line) for line in audit.LOG_PATH.read_text().splitlines()]


def test_success_event_has_utc_timestamp_and_expected_fields():
    audit.audit_event("registration", "alice")
    row, = read_events()
    assert row["event"] == "registration"
    assert row["username"] == "alice"
    assert row["outcome"] == "success"
    assert row["level"] == "INFO"
    assert datetime.fromisoformat(row["timestamp"]).utcoffset().total_seconds() == 0


def test_failed_and_denied_events_are_warnings():
    audit.audit_event("login", "alice", "failure", "invalid_credentials")
    audit.audit_event("entry_list", "alice", "denied", "vault_locked")
    events = read_events()
    assert [(e["event"], e["level"], e["outcome"], e.get("reason"))
            for e in events] == [
        ("login", "WARNING", "failure", "invalid_credentials"),
        ("entry_list", "WARNING", "denied", "vault_locked")]


def test_integrity_failure_is_error():
    audit.audit_event("integrity_failure", "alice", "failure", "account_changed")
    assert read_events()[0]["level"] == "ERROR"


def test_events_do_not_include_passwords_or_keys():
    master = "ThisIsTheMasterPassword!"
    entry = "very-secret-password!"
    audit.audit_event("entry_add", "alice")
    text = audit.LOG_PATH.read_text()
    assert master not in text
    assert entry not in text
    assert "totp_secret" not in text
    assert "vault_key" not in text
    assert set(read_events()[0]) <= {"timestamp", "level", "event", "outcome", "username", "reason"}


@pytest.mark.parametrize("invalid_event,outcome,reason", [
    ("unknown_event", "success", None),
    ("login", "unknown_outcome", None),
    ("login", "failure", "literal password here"),
])
def test_unapproved_audit_values_rejected(invalid_event, outcome, reason):
    with pytest.raises(ValueError):
        audit.audit_event(invalid_event, "alice", outcome, reason)
    assert read_events() == []


def test_invalid_usernames_are_omitted_from_audit_records():
    audit.audit_event("login", "alice\nforged-event", "failure", "invalid_credentials")
    assert "username" not in read_events()[0]
    assert len(read_events()) == 1


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions")
def test_log_file_is_private():
    assert audit.LOG_PATH.stat().st_mode & 0o777 == 0o600


def test_every_audit_line_is_valid_json():
    audit.audit_event("registration", "alice")
    audit.audit_event("totp_enrollment", "alice")
    audit.audit_event("vault_lock", "alice")
    events = read_events()
    assert len(events) == 3
    assert {row["event"] for row in events} == {"registration", "totp_enrollment", "vault_lock"}


def test_real_vault_operation_does_not_log_secret_fields(unlocked_cli, monkeypatch):
    from src import cli

    prompts = iter(["SensitiveService", "private notes"])
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_args: next(prompts))
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_args: "test-entry-password-999")
    unlocked_cli.add_entry()
    rows = read_events()
    assert any(row["event"] == "entry_add" and row["outcome"] == "success" for row in rows)
    text = audit.LOG_PATH.read_text()
    for sensitive in ("SensitiveService", "private notes", "test-entry-password-999"):
        assert sensitive not in text
