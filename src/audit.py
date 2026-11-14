"""Structured security audit events. No secret or free-form exception values."""
import json
import logging
import os
import re
import stat
from datetime import datetime, timezone

from src.accounts import DATA_DIR

LOG_PATH = DATA_DIR / "audit.jsonl"
USERNAME_RE = re.compile(r"[a-z0-9_]{3,32}\Z")
EVENTS = {
    "registration", "login", "logout", "vault_lock", "vault_unlock",
    "entry_add", "entry_list", "entry_find", "entry_copy", "entry_edit",
    "entry_remove", "integrity_failure", "session_end", "input_rejected",
    "unexpected_error",
}
OUTCOMES = {"success", "failure", "denied"}
REASONS = {
    "invalid_input", "password_mismatch", "duplicate_username",
    "invalid_credentials", "authentication_error", "storage_error",
    "operation_failed", "not_authenticated", "vault_locked",
    "account_changed", "clipboard_unavailable", "cancelled",
    "no_changes", "unexpected_error", "interrupted", "eof",
    "terminated", "database_check_failed",
}


class JsonAuditFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.audit_event,
            "outcome": record.outcome,
        }
        if record.username is not None:
            data["username"] = record.username
        if record.reason is not None:
            data["reason"] = record.reason
        return json.dumps(data, ensure_ascii=True, separators=(",", ":"))


def setup_audit_logging():
    logger = logging.getLogger("password_manager.audit")
    if logger.handlers:
        return

    # DATA_DIR must have already been created by initialize_storage().
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOG_PATH, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("Invalid audit log file.")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
    except BaseException:
        os.close(fd)
        raise

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonAuditFormatter())
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)


def audit_event(event, username=None, outcome="success", reason=None):
    if event not in EVENTS or outcome not in OUTCOMES:
        raise ValueError("Invalid audit event or outcome.")
    if reason is not None and reason not in REASONS:
        raise ValueError("Invalid audit reason.")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        username = None

    level = logging.INFO if outcome == "success" else logging.WARNING
    if event == "integrity_failure":
        level = logging.ERROR

    logging.getLogger("password_manager.audit").log(
        level,
        "audit",
        extra={
            "audit_event": event,
            "outcome": outcome,
            "username": username,
            "reason": reason,
        },
    )