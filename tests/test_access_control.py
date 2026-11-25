"""Isolation between accounts and safe CLI session transitions."""
import sqlite3

import pytest
from src import accounts, audit, vault
from src.cli import PasswordManagerCLI


def test_users_have_distinct_keys_and_vault_ids(alice, bob):
    assert alice.snapshot[0] != bob.snapshot[0]
    assert alice.dek != bob.dek
    assert (accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault").exists()
    assert (accounts.VAULT_DIR / f"{bob.snapshot[0]}.vault").exists()


def test_each_user_only_decrypts_their_own_vault(alice, bob):
    vault.add_entry("alice", alice.dek, "private-alice", "secret-a", "")
    vault.add_entry("bob", bob.dek, "private-bob", "secret-b", "")
    assert vault.list_entries("alice", alice.dek) == ["private-alice"]
    assert vault.list_entries("bob", bob.dek) == ["private-bob"]
    with pytest.raises(vault.VaultError):
        vault.get_entry_password("alice", bob.dek, "private-alice")
    with pytest.raises(vault.VaultError):
        vault.get_entry_password("bob", alice.dek, "private-bob")


@pytest.mark.parametrize("method", [
    "add_entry", "list_entries", "find_entry", "copy_entry", "edit_entry", "remove_entry"
])
def test_vault_commands_denied_when_logged_out(method, capsys):
    app = PasswordManagerCLI()
    getattr(app, method)()
    assert "log in" in capsys.readouterr().out.lower()


@pytest.mark.parametrize("method", [
    "add_entry", "list_entries", "find_entry", "copy_entry", "edit_entry", "remove_entry"
])
def test_vault_commands_denied_when_locked(unlocked_cli, method, capsys):
    unlocked_cli.lock_vault()
    getattr(unlocked_cli, method)()
    assert "locked" in capsys.readouterr().out.lower()
    assert unlocked_cli.vault_key is None


def test_lock_does_not_end_authenticated_session(unlocked_cli, alice):
    unlocked_cli.lock_vault()
    assert unlocked_cli.current_user == alice.username
    assert unlocked_cli.account_snapshot == alice.snapshot
    assert unlocked_cli.vault_key is None


def test_unlock_only_uses_master_password(unlocked_cli, alice, monkeypatch):
    from src import cli

    unlocked_cli.lock_vault()
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: alice.master_password)
    unlocked_cli.unlock_vault()
    assert unlocked_cli.vault_key == alice.dek


def test_wrong_unlock_password_keeps_vault_locked(unlocked_cli, monkeypatch):
    from src import cli

    unlocked_cli.lock_vault()
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "invalid-master")
    unlocked_cli.unlock_vault()
    assert unlocked_cli.vault_key is None


def test_account_change_ends_current_session(unlocked_cli, alice, capsys):
    with sqlite3.connect(accounts.DB_PATH) as db:
        db.execute("UPDATE users SET wrapped_dek = ? WHERE username = ?",
                   (b"tampered", alice.username))
    assert unlocked_cli.check_session_integrity() is False
    assert unlocked_cli.current_user is None
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.account_snapshot is None
    assert "integrity" in capsys.readouterr().out.lower()


def test_database_query_uses_parameterized_username(alice):
    malicious = "alice' OR 1=1 --"
    assert accounts.authenticate_user(malicious, alice.master_password) is None
    assert accounts.read_account_snapshot(malicious) is None
    assert accounts.username_exists("alice")


@pytest.mark.parametrize("operation", [
    "list", "find", "copy", "add", "edit", "remove",
])
def test_wrong_dek_rejected_for_every_vault_operation(alice, bob, operation):
    vault.add_entry("alice", alice.dek, "private", "alice-password", "alice-notes")
    actions = {
        "list": lambda: vault.list_entries("alice", bob.dek),
        "find": lambda: vault.find_entry("alice", bob.dek, "private"),
        "copy": lambda: vault.get_entry_password("alice", bob.dek, "private"),
        "add": lambda: vault.add_entry("alice", bob.dek, "new", "password", ""),
        "edit": lambda: vault.edit_entry("alice", bob.dek, "private", new_password="bad"),
        "remove": lambda: vault.remove_entry("alice", bob.dek, "private"),
    }
    with pytest.raises(vault.VaultError):
        actions[operation]()
    assert vault.list_entries("alice", alice.dek) == ["private"]
    assert vault.get_entry_password("alice", alice.dek, "private") == "alice-password"
