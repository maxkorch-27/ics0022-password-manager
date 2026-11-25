"""Boundaries and malicious or malformed inputs, including explicit security goals."""
import pytest
from src import accounts, vault
from conftest import MASTER_PASSWORD


@pytest.mark.parametrize("username", [
    "", "ab", "AlicE", "with-hyphen", "with space", "a" * 33,
    "alice\n", "älice", "a.b", "user;DROP TABLE users;--",
])
def test_invalid_usernames_rejected(username):
    with pytest.raises(ValueError):
        accounts.validate_registration_input(username, MASTER_PASSWORD)


@pytest.mark.parametrize("username", ["abc", "user_42", "a" * 32])
def test_valid_usernames_accepted(username):
    accounts.validate_registration_input(username, MASTER_PASSWORD)


@pytest.mark.parametrize("password", ["", "short", "x" * 11, "x" * 129, " " * 12])
def test_invalid_master_password_lengths_and_all_whitespace(password):
    with pytest.raises(ValueError):
        accounts.validate_registration_input("alice", password)


def test_master_password_valid_boundaries():
    for password in ("x" * 12, "x" * 128, "pässphrase-über-12"):
        accounts.validate_registration_input("alice", password)


def test_registration_rejects_wrong_input_types():
    for username, password in [(None, MASTER_PASSWORD), (42, MASTER_PASSWORD),
                               ("alice", None), ("alice", 123)]:
        with pytest.raises(ValueError):
            accounts.validate_registration_input(username, password)


@pytest.mark.parametrize("name", ["", " ", "\t", "x" * 101])
def test_add_rejects_blank_or_oversized_service_name(alice, name):
    with pytest.raises(ValueError):
        vault.add_entry("alice", alice.dek, name, "valid-password", "")


@pytest.mark.parametrize("password", ["", "x" * 257])
def test_add_rejects_invalid_entry_password_length(alice, password):
    with pytest.raises(ValueError):
        vault.add_entry("alice", alice.dek, "service", password, "")


def test_add_rejects_oversized_notes(alice):
    with pytest.raises(ValueError):
        vault.add_entry("alice", alice.dek, "service", "valid-password", "x" * 1001)


def test_entry_field_maximum_lengths_accepted(alice):
    vault.add_entry("alice", alice.dek, "s" * 100, "p" * 256, "n" * 1000)
    assert vault.get_entry_password("alice", alice.dek, "s" * 100) == "p" * 256


def test_edit_rejects_oversized_fields_without_mutation(alice):
    vault.add_entry("alice", alice.dek, "service", "old-password", "old notes")
    changes = [
        {"new_service_name": "x" * 101},
        {"new_password": "x" * 257},
        {"new_notes": "x" * 1001},
    ]
    for change in changes:
        with pytest.raises(ValueError):
            vault.edit_entry("alice", alice.dek, "service", **change)
    assert vault.get_entry_password("alice", alice.dek, "service") == "old-password"
    assert vault.find_entry("alice", alice.dek, "service")["notes"] == "old notes"


def test_edit_can_clear_notes(alice):
    vault.add_entry("alice", alice.dek, "service", "pw", "private note")
    assert vault.edit_entry("alice", alice.dek, "service", new_notes="")
    assert vault.find_entry("alice", alice.dek, "service")["notes"] == ""


@pytest.mark.parametrize("name", ["bad\x00name", "bad\x1bname", "bad\nname", "bad\rname"])
def test_control_characters_in_service_names_are_rejected(alice, name):
    """Required hardened behavior; old vault.py versions may FAIL this test."""
    with pytest.raises(ValueError):
        vault.add_entry("alice", alice.dek, name, "password", "")


def test_read_bounded_line_rejects_oversize_and_discards_the_line(monkeypatch):
    """Oversize input may not spill into the next CLI command."""
    import io
    from src import cli

    stream = io.StringIO("x" * 90 + "\nhelp\n")
    monkeypatch.setattr(cli.sys, "stdin", stream)
    with pytest.raises(ValueError):
        cli.read_bounded_line("prompt: ", 32)
    assert cli.read_bounded_line("prompt: ", 32) == "help"


def test_read_bounded_line_raises_eof_on_empty_stream(monkeypatch):
    import io
    from src import cli

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    with pytest.raises(EOFError):
        cli.read_bounded_line("prompt: ", 32)
