"""Verify reference cleanup; does NOT claim secure overwriting of Python RAM."""
import signal

import pytest
from src import cli


def test_clear_session_drops_key_username_and_snapshot(unlocked_cli):
    unlocked_cli.clear_session()
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.current_user is None
    assert unlocked_cli.account_snapshot is None


def test_lock_drops_vault_key_but_preserves_session(unlocked_cli):
    old_username = unlocked_cli.current_user
    unlocked_cli.lock_vault()
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.current_user == old_username


def test_logout_clears_all_session_references(unlocked_cli):
    unlocked_cli.logout()
    assert unlocked_cli.current_user is None
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.account_snapshot is None


def test_eof_clears_session_in_finally(unlocked_cli, monkeypatch):
    def eof(*_args):
        raise EOFError

    monkeypatch.setattr(cli, "read_bounded_line", eof)
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
    unlocked_cli.run()
    assert unlocked_cli.current_user is None
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.account_snapshot is None
    assert not unlocked_cli.running


def test_keyboard_interrupt_clears_session(unlocked_cli, monkeypatch):
    def interrupted(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "read_bounded_line", interrupted)
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
    unlocked_cli.run()
    assert unlocked_cli.current_user is None
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.account_snapshot is None
    assert unlocked_cli.exit_reason == "interrupted"


def test_termination_signal_clears_session(unlocked_cli, monkeypatch):
    def terminate(*_args):
        unlocked_cli.handle_termination(signal.SIGTERM, None)

    monkeypatch.setattr(cli, "read_bounded_line", terminate)
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: None)
    with pytest.raises(SystemExit):
        unlocked_cli.run()
    assert unlocked_cli.current_user is None
    assert unlocked_cli.vault_key is None
    assert unlocked_cli.account_snapshot is None


def test_copy_entry_does_not_keep_password_attribute(unlocked_cli, alice, monkeypatch):
    from src import vault

    vault.add_entry("alice", alice.dek, "service", "very-secret-copy-value", "")
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_args: "service")
    captured = []
    monkeypatch.setattr(cli, "copy_to_clipboard", captured.append)
    unlocked_cli.copy_entry()
    assert captured == ["very-secret-copy-value"]
    assert "password" not in unlocked_cli.__dict__
    assert unlocked_cli.vault_key == alice.dek
