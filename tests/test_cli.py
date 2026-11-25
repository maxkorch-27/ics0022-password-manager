"""End-to-end CLI enrollment/login without real terminal prompts or a clipboard."""
import pyotp
from src import accounts, cli, vault
from conftest import MASTER_PASSWORD, TEST_TIME


class DummyQRCode:
    def __init__(self, **kwargs):
        self.data = None

    def add_data(self, data):
        self.data = data

    def make(self, fit=True):
        pass

    def print_ascii(self, invert=True):
        pass


def _feed_getpass(monkeypatch, values):
    answers = iter(values)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))


def test_cli_register_requires_confirmed_totp(monkeypatch):
    account = cli.PasswordManagerCLI()
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_: "alice")
    monkeypatch.setattr(cli.qrcode, "QRCode", DummyQRCode)
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    monkeypatch.setattr(cli.pyotp, "random_base32", lambda: secret)
    code = pyotp.TOTP(secret).now()
    _feed_getpass(monkeypatch, [MASTER_PASSWORD, MASTER_PASSWORD, code])
    account.register()
    assert accounts.username_exists("alice")
    assert account.current_user is None  # registration must not auto-login


def test_cli_registration_rejected_after_three_invalid_totp_codes(monkeypatch):
    app = cli.PasswordManagerCLI()
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_: "alice")
    monkeypatch.setattr(cli.qrcode, "QRCode", DummyQRCode)
    _feed_getpass(monkeypatch, [MASTER_PASSWORD, MASTER_PASSWORD, "", "", ""])
    app.register()
    assert not accounts.username_exists("alice")


def test_cli_login_requires_both_factors(alice, freeze_account_time, monkeypatch):
    freeze_account_time()
    app = cli.PasswordManagerCLI()
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_: "alice")
    code = pyotp.TOTP(alice.totp_secret).at(TEST_TIME)
    _feed_getpass(monkeypatch, [alice.master_password, code])
    app.login()
    assert app.current_user == "alice"
    assert app.vault_key == alice.dek
    assert app.account_snapshot == alice.snapshot


def test_cli_failed_2fa_does_not_activate_session(alice, freeze_account_time, monkeypatch):
    freeze_account_time()
    app = cli.PasswordManagerCLI()
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_: "alice")
    _feed_getpass(monkeypatch, [alice.master_password, "invalid"])
    app.login()
    assert app.current_user is None
    assert app.vault_key is None
    assert app.account_snapshot is None


def test_cli_add_find_copy_edit_remove(unlocked_cli, monkeypatch, capsys):
    # Each CLI call consumes exactly the stated prompts.
    lines = iter(["GitLab", "note", "GitLab", "GitLab", "GitLab", "", "/clear", "GitLab", "yes"])
    monkeypatch.setattr(cli, "read_bounded_line", lambda *_: next(lines))
    _feed_getpass(monkeypatch, ["entry-pass", "entry-pass", "", ""])
    clipboard = []
    monkeypatch.setattr(cli, "copy_to_clipboard", clipboard.append)
    unlocked_cli.add_entry()
    unlocked_cli.find_entry()
    unlocked_cli.copy_entry()
    unlocked_cli.edit_entry()
    unlocked_cli.remove_entry()
    assert clipboard == ["entry-pass"]
    assert vault.list_entries("alice", unlocked_cli.vault_key) == []
    assert "entry-pass" not in capsys.readouterr().out
