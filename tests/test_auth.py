"""Registration, password verification, storage, and database integrity."""
import os
import sqlite3

import pytest
from src import accounts
from conftest import MASTER_PASSWORD


def test_storage_is_initialized_with_expected_schema(isolated_environment):
    accounts.check_database_integrity()
    with sqlite3.connect(accounts.DB_PATH) as db:
        cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    assert {"username", "password_hash", "wrapped_dek", "totp_ciphertext",
            "totp_last_step", "failed_login_attempts", "login_blocked_until"} <= cols
    assert accounts.VAULT_DIR.is_dir()


def test_registration_creates_distinct_encrypted_vault_and_account(alice):
    assert accounts.username_exists("alice")
    assert not accounts.username_exists("unknown")
    assert alice.snapshot == accounts.read_account_snapshot("alice")
    vault_path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault"
    assert vault_path.is_file()
    assert b'"entries"' not in vault_path.read_bytes()
    assert MASTER_PASSWORD.encode() not in accounts.DB_PATH.read_bytes()


def test_registration_uses_argon2id_and_unique_salt(make_account):
    first = make_account("alice")
    second = make_account("bob", MASTER_PASSWORD)
    with sqlite3.connect(accounts.DB_PATH) as db:
        a = db.execute("SELECT password_hash, kek_salt FROM users WHERE username='alice'").fetchone()
        b = db.execute("SELECT password_hash, kek_salt FROM users WHERE username='bob'").fetchone()
    assert a[0].startswith("$argon2id$")
    assert a[0] != b[0]
    assert a[1] != b[1]
    assert first.dek != second.dek


def test_duplicate_username_has_no_orphan_vault(alice, make_account):
    before = set(accounts.VAULT_DIR.glob("*.vault"))
    with pytest.raises(accounts.AccountExistsError):
        make_account("alice")
    assert set(accounts.VAULT_DIR.glob("*.vault")) == before


def test_correct_and_incorrect_master_password(alice):
    assert accounts.authenticate_user("alice", alice.master_password)[0] == alice.dek
    assert accounts.authenticate_user("alice", "totally-wrong-password") is None
    assert accounts.authenticate_user("nonexistent", alice.master_password) is None


def test_session_snapshot_changes_after_account_tampering(alice):
    assert accounts.read_account_snapshot("alice") == alice.snapshot
    with sqlite3.connect(accounts.DB_PATH) as db:
        db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                   ("tampered", "alice"))
    assert accounts.read_account_snapshot("alice") != alice.snapshot


def test_modified_vault_ciphertext_fails_authentication(alice):
    path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault"
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(RuntimeError, match="Vault authentication failed"):
        accounts.authenticate_user("alice", alice.master_password)


@pytest.mark.skipif(os.name != "posix", reason="Unix file permissions")
def test_private_permissions(alice):
    paths = [accounts.DATA_DIR, accounts.VAULT_DIR]
    assert all((p.stat().st_mode & 0o777) == 0o700 for p in paths)
    assert accounts.DB_PATH.stat().st_mode & 0o777 == 0o600
    assert (accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault").stat().st_mode & 0o777 == 0o600
