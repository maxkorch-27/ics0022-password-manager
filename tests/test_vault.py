"""CRUD, encryption, authenticated storage and error handling."""
import pytest
from src import accounts, vault

ENTRY_PASSWORD = "ExampleEntryPassword#33"


def test_vault_starts_empty(alice):
    assert vault.list_entries("alice", alice.dek) == []


def test_add_list_find_copy_edit_remove_roundtrip(alice):
    entry_id = vault.add_entry("alice", alice.dek, "GitLab", ENTRY_PASSWORD, "Work notes")
    assert len(entry_id) == 32
    assert vault.list_entries("alice", alice.dek) == ["GitLab"]
    assert vault.find_entry("alice", alice.dek, "gitlab") == {
        "service_name": "GitLab", "notes": "Work notes"}
    assert vault.get_entry_password("alice", alice.dek, " GITLAB ") == ENTRY_PASSWORD
    assert vault.edit_entry("alice", alice.dek, "gitlab", new_password="new-secret", new_notes="changed")
    assert vault.get_entry_password("alice", alice.dek, "GitLab") == "new-secret"
    assert vault.find_entry("alice", alice.dek, "GitLab")["notes"] == "changed"
    vault.remove_entry("alice", alice.dek, "GITLAB")
    assert vault.list_entries("alice", alice.dek) == []


def test_service_names_are_unique_ignoring_case_and_spaces(alice):
    vault.add_entry("alice", alice.dek, " GitLab ", ENTRY_PASSWORD, "")
    with pytest.raises(vault.VaultError):
        vault.add_entry("alice", alice.dek, "gitlab", "second", "")
    assert vault.list_entries("alice", alice.dek) == ["GitLab"]


def test_entry_password_never_appears_in_vault_file(alice):
    vault.add_entry("alice", alice.dek, "bank", ENTRY_PASSWORD, "Private notes")
    path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault"
    ciphertext = path.read_bytes()
    for secret in (b"bank", b"Private notes", ENTRY_PASSWORD.encode()):
        assert secret not in ciphertext


def test_ciphertext_changes_on_resave_due_to_random_nonce(alice):
    path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault"
    initial = path.read_bytes()
    doc, user_id = vault.load_vault("alice", alice.dek)
    vault.save_vault(doc, user_id, alice.dek)
    assert path.read_bytes() != initial
    assert vault.load_vault("alice", alice.dek)[0] == doc


def test_tampering_with_ciphertext_is_detected(alice):
    path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.vault"
    damaged = bytearray(path.read_bytes())
    damaged[-1] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(vault.VaultError):
        vault.list_entries("alice", alice.dek)


def test_wrong_dek_cannot_read_vault(alice, bob):
    with pytest.raises(vault.VaultError):
        vault.load_vault("alice", bob.dek)


def test_edit_without_changes_returns_false(alice):
    vault.add_entry("alice", alice.dek, "GitLab", ENTRY_PASSWORD, "")
    assert vault.edit_entry("alice", alice.dek, "GitLab") is False


def test_edit_to_existing_name_is_rejected(alice):
    vault.add_entry("alice", alice.dek, "GitLab", "first", "")
    vault.add_entry("alice", alice.dek, "GitHub", "second", "")
    with pytest.raises(vault.VaultError):
        vault.edit_entry("alice", alice.dek, "GitLab", new_service_name="github")
    assert vault.list_entries("alice", alice.dek) == ["GitHub", "GitLab"]


def test_editing_service_name_preserves_case(alice):
    vault.add_entry("alice", alice.dek, "GitLab", ENTRY_PASSWORD, "")
    vault.edit_entry("alice", alice.dek, "GitLab", new_service_name="NewService")
    assert vault.list_entries("alice", alice.dek) == ["NewService"]


def test_absent_entries_raise_without_changing_vault(alice):
    original = vault.list_entries("alice", alice.dek)
    with pytest.raises(vault.VaultError):
        vault.get_entry_password("alice", alice.dek, "not found")
    with pytest.raises(vault.VaultError):
        vault.find_entry("alice", alice.dek, "not found")
    with pytest.raises(vault.VaultError):
        vault.remove_entry("alice", alice.dek, "not found")
    assert vault.list_entries("alice", alice.dek) == original


def test_vault_size_limit_prevents_oversized_save(alice, monkeypatch):
    document, user_id = vault.load_vault("alice", alice.dek)
    document["entries"] = [{"service_name": "huge", "password": "x" * 100, "notes": ""}]
    monkeypatch.setattr(vault, "MAX_VAULT_BYTES", 64)
    with pytest.raises(vault.VaultError, match="size"):
        vault.save_vault(document, user_id, alice.dek)
