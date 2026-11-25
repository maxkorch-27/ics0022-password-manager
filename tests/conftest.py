"""Shared fixtures. NEVER use the real project database or vault directory."""
from dataclasses import dataclass
from pathlib import Path
import logging
import os

import pytest
from argon2 import PasswordHasher

from src import accounts, audit, vault

MASTER_PASSWORD = "Correct-Horse-Battery-77!"
SECOND_PASSWORD = "Another-Strong-Pass-99!"
TEST_TIME = 1_760_000_010  # fixed time enables deterministic TOTP cases


@dataclass(frozen=True)
class TestAccount:
    username: str
    master_password: str
    totp_secret: str
    dek: bytes
    snapshot: tuple


def _close_audit_handlers():
    logger = logging.getLogger("password_manager.audit")

    for handler in list(logger.handlers):
        # Only close handlers created by our audit module.
        if not isinstance(handler.formatter, audit.JsonAuditFormatter):
            continue
        logger.removeHandler(handler)
        stream = getattr(handler, "stream", None)
        if stream is not None and not stream.closed:
            handler.flush()
            stream.close()

        handler.close()


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    """Redirect *every* data path to pytest tmp_path before initializing storage.

    Test-only reduced Argon2 cost keeps the suite reasonably fast. The actual
    algorithm is unchanged and production parameters are not modified on disk.
    """
    _close_audit_handlers()
    data_dir = tmp_path / "data"
    vault_dir = data_dir / "vaults"
    monkeypatch.setattr(accounts, "DATA_DIR", data_dir)
    monkeypatch.setattr(accounts, "DB_PATH", data_dir / "users.db")
    monkeypatch.setattr(accounts, "VAULT_DIR", vault_dir)
    monkeypatch.setattr(vault, "DB_PATH", data_dir / "users.db")
    monkeypatch.setattr(vault, "VAULT_DIR", vault_dir)
    monkeypatch.setattr(audit, "LOG_PATH", data_dir / "audit.jsonl")
    monkeypatch.setattr(accounts, "TIME_COST", 2)
    monkeypatch.setattr(accounts, "MEMORY_COST", 8192)
    monkeypatch.setattr(accounts, "PARALLELISM", 1)
    monkeypatch.setattr(
        accounts, "HASHER",
        PasswordHasher(time_cost=2, memory_cost=8192, parallelism=1),
    )
    accounts.initialize_storage()
    audit.setup_audit_logging()
    try:
        yield data_dir
    finally:
        _close_audit_handlers()


@pytest.fixture
def make_account():
    import pyotp

    def create(username="alice", password=MASTER_PASSWORD):
        secret = pyotp.random_base32()
        accounts.register_user(username, password, secret)
        result = accounts.authenticate_user(username, password)
        assert result is not None
        dek, snapshot = result
        return TestAccount(username, password, secret, dek, snapshot)

    return create


@pytest.fixture
def alice(make_account):
    return make_account()


@pytest.fixture
def bob(make_account):
    return make_account("bob", SECOND_PASSWORD)


@pytest.fixture
def freeze_account_time(monkeypatch):
    """Replace only accounts' time reference, not Python's global time module."""
    from types import SimpleNamespace

    def freeze(epoch=TEST_TIME):
        monkeypatch.setattr(accounts, "time", SimpleNamespace(time=lambda: epoch))
        return epoch

    return freeze


@pytest.fixture
def unlocked_cli(alice):
    from src.cli import PasswordManagerCLI

    app = PasswordManagerCLI()
    app.current_user = alice.username
    app.vault_key = alice.dek
    app.account_snapshot = alice.snapshot
    return app
