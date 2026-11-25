import json
import os
import secrets
import sqlite3
import tempfile
import uuid
from pathlib import Path
import fcntl
from functools import wraps

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.accounts import DB_PATH, VAULT_DIR

MAX_VAULT_BYTES = 5 * 1024 * 1024

class VaultError(Exception):
    pass

def load_vault(username, dek):
    with sqlite3.connect(DB_PATH) as db:
        user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    if user is None:
        raise VaultError("User account not found.")

    user_id = user[0]
    vault_path = VAULT_DIR / f"{user_id}.vault"
    aad = b"pm-vault-v1:" + user_id.encode("utf-8")
    try:
        with vault_path.open("rb") as f:
            stored = f.read(MAX_VAULT_BYTES + 1)
        if len(stored) > MAX_VAULT_BYTES or len(stored) < 28:
            raise VaultError("Invalid vault size.")
        plaintext = AESGCM(dek).decrypt(
            stored[:12],
            stored[12:],
            aad
        )
        document = json.loads(plaintext)
    except (OSError, InvalidTag, ValueError, UnicodeError) as exc:
        raise VaultError("Could not read or decrypt vault.") from exc
    if (
        not isinstance(document, dict)
        or document.get("version") != 1
        or not isinstance(document.get("entries"), list)
    ):
        raise VaultError("Invalid vault format.")

    return document, user_id

def save_vault(document, user_id, dek):
    vault_path = VAULT_DIR / f"{user_id}.vault"
    aad = b"pm-vault-v1:" + user_id.encode("utf-8")
    plaintext = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")
    nonce = secrets.token_bytes(12)

    encrypted = nonce + AESGCM(dek).encrypt(
        nonce,
        plaintext,
        aad
    )

    if len(encrypted) > MAX_VAULT_BYTES:
        raise VaultError("Invalid vault size.")
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=VAULT_DIR,
            prefix=f".{user_id}.",
            suffix=".tmp"
        )

        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as f:
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, vault_path)
    except OSError as exc:
        raise VaultError("Failed to save the encrypted vault.") from exc
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

def locked_vault_write(func):
    @wraps(func)
    def wrapper(username, dek, *args, **kwargs):
        with sqlite3.connect(DB_PATH) as db:
            user = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        if user is None:
            raise VaultError("User account not found.")
        user_id = user[0]
        lock_path = VAULT_DIR / f"{user_id}.lock"
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(lock_path, flags, 0o600)
            with os.fdopen(fd, "r+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    return func(username, dek, *args, **kwargs)
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise VaultError("Vault locking failed.") from exc
    return wrapper

@locked_vault_write
def add_entry(username, dek, service_name, password, notes):
    if not 1 <= len(service_name) <= 100 or not service_name.strip() or not service_name.isprintable():
        raise ValueError("Invalid service name.")
    if not 1 <= len(password) <= 256:
        raise ValueError("Entry password must be 1-256 characters.")
    if len(notes) > 1000:
        raise ValueError("Notes must be at most 1000 characters.")

    document, user_id = load_vault(username, dek)

    normalized_name = service_name.strip().casefold()
    for entry in document["entries"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("service_name"), str):
            raise VaultError("Vault entry format is invalid.")

        if entry["service_name"].strip().casefold() == normalized_name:
            raise VaultError(
                f"An entry for '{service_name}' already exists. Use 'edit' instead."
            )

    entry_id = uuid.uuid4().hex
    document["entries"].append({
        "id": entry_id,
        "service_name": service_name.strip(),
        "password": password,
        "notes": notes,
    })
    save_vault(document, user_id, dek)
    return entry_id

def list_entries(username, dek):
    document, _ = load_vault(username, dek)

    services = []
    for entry in document["entries"]:
        if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("service_name"), str)
        ):
            raise VaultError("Invalid vault entry format.")
        services.append(entry["service_name"])

    return sorted(services, key=str.casefold)

def get_entry_password(username, dek, service_name):
    document, _ = load_vault(username, dek)
    normalized_name = service_name.strip().casefold()
    for entry in document["entries"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("service_name"), str)
            or not isinstance(entry.get("password"), str)
        ):
            raise VaultError("Vault entry format is invalid.")
        if entry["service_name"].strip().casefold() == normalized_name:
            return entry["password"]
    raise VaultError("Entry not found.")

def find_entry(username, dek, service_name):
    document, _ = load_vault(username, dek)

    normalized_name = service_name.strip().casefold()
    for entry in document["entries"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("service_name"), str)
            or not isinstance(entry.get("notes"), str)
        ):
            raise VaultError("Vault entry format is invalid.")

        if entry["service_name"].strip().casefold() == normalized_name:
            return {
                "service_name": entry["service_name"],
                "notes": entry["notes"]
            }
    raise VaultError("Entry not found.")

@locked_vault_write
def edit_entry(username, dek, service_name, new_service_name=None, new_password=None, new_notes=None):
    document, user_id = load_vault(username, dek)
    normalized_name = service_name.strip().casefold()
    target_entry = None
    for entry in document["entries"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("service_name"), str)
            or not isinstance(entry.get("password"), str)
            or not isinstance(entry.get("notes"), str)
        ):
            raise VaultError("Vault entry format is invalid.")
        if entry["service_name"].strip().casefold() == normalized_name:
            target_entry = entry
            break
    if target_entry is None:
        raise VaultError("Entry not found.")
    if new_service_name is not None:
        new_service_name = new_service_name.strip()
        if not 1 <= len(new_service_name) <= 100 or not new_service_name.strip() or not new_service_name.isprintable():
            raise ValueError("Invalid service name.")
        normalized_new_name = new_service_name.casefold()
        for entry in document["entries"]:
            if entry is target_entry:
                continue
            if entry["service_name"].strip().casefold() == normalized_new_name:
                raise VaultError("Service name already exists.")
        target_entry["service_name"] = new_service_name
    if new_password is not None:
        if not 1 <= len(new_password) <= 256:
            raise ValueError("New password must be 1-256 characters.")
        target_entry["password"] = new_password
    if new_notes is not None:
        if len(new_notes) > 1000:
            raise ValueError("New notes must be at most 1000 characters.")
        target_entry["notes"] = new_notes
    if all(value is None for value in (
            new_service_name, new_password, new_notes)):
        return False
    save_vault(document, user_id, dek)
    return True

@locked_vault_write
def remove_entry(username, dek, service_name):
    document, user_id = load_vault(username, dek)
    normalized_name = service_name.strip().casefold()
    target_index = None

    for index, entry in enumerate(document["entries"]):
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("service_name"), str)
        ):
            raise VaultError("Vault entry format is invalid.")
        if entry["service_name"].strip().casefold() == normalized_name:
            target_index = index
            break
    if target_index is None:
        raise VaultError("Entry not found.")
    document["entries"].pop(target_index)
    save_vault(document, user_id, dek)