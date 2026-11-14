import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_DIR = Path(__file__).resolve().parent.parent / 'data'
DB_PATH = DATA_DIR / 'users.db'
VAULT_DIR = DATA_DIR / 'vaults'
USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,32}\Z")
TOTP_CODE_PATTERN = re.compile(r"[0-9]{6}\Z")
TOTP_SECRET_PATTERN = re.compile(r"[A-Z2-7]{32}\Z")

TIME_COST = 3
MEMORY_COST = 65536
PARALLELISM = 2
HASHER = PasswordHasher(time_cost=TIME_COST, memory_cost=MEMORY_COST, parallelism=PARALLELISM)
MAX_VAULT_BYTES = 5*1024*1024

SNAPSHOT_COLUMNS = (
    "id", "username", "password_hash", "kek_salt", "kek_time_cost",
    "kek_memory_cost", "kek_parallelism", "dek_nonce", "wrapped_dek",
    "totp_nonce", "totp_ciphertext",
)
SNAPSHOT_SQL = ", ".join(SNAPSHOT_COLUMNS)

MAX_FAILED_LOGINS = 3
LOGIN_COOLDOWN_SECONDS = 60

class AccountExistsError(Exception):
    pass

def initialize_storage():
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)
    if os.name == 'posix':
        os.chmod(DATA_DIR, 0o700)
        os.chmod(VAULT_DIR, 0o700)

    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        with db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    kek_salt BLOB NOT NULL,
                    kek_time_cost INTEGER NOT NULL,
                    kek_memory_cost INTEGER NOT NULL,
                    kek_parallelism INTEGER NOT NULL,
                    dek_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    totp_nonce BLOB NOT NULL,
                    totp_ciphertext BLOB NOT NULL,
                    totp_last_step INTEGER NOT NULL DEFAULT -1,
                    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                    login_blocked_until INTEGER NOT NULL DEFAULT 0
                )
            """)

    if os.name == 'posix':
        os.chmod(DB_PATH, 0o600)

    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        actual_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if not set(SNAPSHOT_COLUMNS).issubset(actual_columns) or not {
        "totp_last_step", "failed_login_attempts", "login_blocked_until"
    }.issubset(actual_columns):
        raise RuntimeError("Incompatible account database schema.")


def check_database_integrity():
    try:
        with closing(sqlite3.connect(DB_PATH.as_uri() + "?mode=ro", uri=True)) as db:
            result = db.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError("Database integrity check failed.") from exc
    if result != [("ok",)]:
        raise RuntimeError("Database integrity check failed.")

def read_account_snapshot(username):
    with closing(sqlite3.connect(DB_PATH.as_uri() + "?mode=ro", uri=True)) as db:
        result = db.execute(
            f"SELECT {SNAPSHOT_SQL} FROM users WHERE username = ?", (username,)
        ).fetchone()
    return tuple(result) if result is not None else None

def username_exists(username):
    with closing(sqlite3.connect(DB_PATH.as_uri() + "?mode=ro", uri=True)) as db:
        return db.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone() is not None

def validate_registration_input(username, master_password):
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3-32 characters: lowercase letters, digits or _.")
    if (not isinstance(master_password, str)
            or not 12 <= len(master_password) <= 128
            or master_password.isspace()):
        raise ValueError("Master password must contain 12-128 characters.")

def derive_kek(password, salt, time_cost, memory_cost, parallelism):
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt,
        time_cost=time_cost, memory_cost=memory_cost,
        parallelism=parallelism, hash_len=32, type=Type.ID,
    )

def register_user(username, master_password, totp_secret):
    validate_registration_input(username, master_password)
    if not isinstance(totp_secret, str) or not TOTP_SECRET_PATTERN.fullmatch(totp_secret):
        raise ValueError("Invalid TOTP enrollment secret.")

    user_id = uuid.uuid4().hex
    password_hash = HASHER.hash(master_password)
    salt = secrets.token_bytes(16)
    kek = derive_kek(master_password, salt, TIME_COST, MEMORY_COST, PARALLELISM)
    dek = AESGCM.generate_key(bit_length=256)
    dek_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(kek).encrypt(
        dek_nonce, dek, b"pm-dek-v1:" + user_id.encode("utf-8")
    )
    totp_nonce = secrets.token_bytes(12)
    totp_ciphertext = AESGCM(dek).encrypt(
        totp_nonce, totp_secret.encode("ascii"),
        b"pm-totp-v1:" + user_id.encode("utf-8"),
    )

    vault_nonce = secrets.token_bytes(12)
    empty_vault = json.dumps({"version": 1, "entries": []}).encode("utf-8")
    vault_ciphertext = AESGCM(dek).encrypt(
        vault_nonce, empty_vault, b"pm-vault-v1:" + user_id.encode("utf-8")
    )
    vault_path = VAULT_DIR / f"{user_id}.vault"

    created_vault = False
    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        try:
            with db:
                db.execute("""
                    INSERT INTO users (
                        id, username, password_hash, kek_salt,
                        kek_time_cost, kek_memory_cost, kek_parallelism,
                        dek_nonce, wrapped_dek, totp_nonce, totp_ciphertext
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, username, password_hash, salt,
                    TIME_COST, MEMORY_COST, PARALLELISM,
                    dek_nonce, wrapped_dek, totp_nonce, totp_ciphertext,
                ))
                fd = os.open(
                    vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                created_vault = True
                with os.fdopen(fd, "wb") as f:
                    f.write(vault_nonce + vault_ciphertext)
                    f.flush()
                    os.fsync(f.fileno())
        except sqlite3.IntegrityError as exc:
            if created_vault:
                vault_path.unlink(missing_ok=True)
            raise AccountExistsError("Username already exists.") from exc
        except BaseException:
            if created_vault:
                vault_path.unlink(missing_ok=True)
            raise

def authenticate_user(username, master_password):
    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        db.row_factory = sqlite3.Row
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    if user is None:
        return None
    try:
        HASHER.verify(user["password_hash"], master_password)
    except VerifyMismatchError:
        return None
    except (VerificationError, InvalidHashError) as exc:
        raise RuntimeError("Account verification failed.") from exc
    kek = derive_kek(
        master_password, user["kek_salt"], user["kek_time_cost"],
        user["kek_memory_cost"], user["kek_parallelism"],
    )
    try:
        dek = AESGCM(kek).decrypt(
            user["dek_nonce"], user["wrapped_dek"],
            b"pm-dek-v1:" + user["id"].encode("utf-8"),
        )
        path = VAULT_DIR / f"{user['id']}.vault"
        with path.open("rb") as f:
            contents = f.read(MAX_VAULT_BYTES + 1)
        if not 28 <= len(contents) <= MAX_VAULT_BYTES:
            raise ValueError("Invalid vault size")
        AESGCM(dek).decrypt(
            contents[:12], contents[12:],
            b"pm-vault-v1:" + user["id"].encode("utf-8"),
        )
    except (InvalidTag, OSError, ValueError, TypeError) as exc:
        raise RuntimeError("Vault authentication failed.") from exc

    snapshot = tuple(user[column] for column in SNAPSHOT_COLUMNS)
    return dek, snapshot

def _is_login_blocked(username, now):
    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        row = db.execute(
            "SELECT login_blocked_until FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None and row[0] > now

def _record_login_failure(username, now):
    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        with db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT failed_login_attempts, login_blocked_until FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None or row[1] > now:
                return
            previous = 0 if row[1] != 0 and row[1] <= now else row[0]
            failures = previous + 1
            blocked_until = now + LOGIN_COOLDOWN_SECONDS if failures >= MAX_FAILED_LOGINS else 0
            db.execute("""
                UPDATE users
                SET failed_login_attempts = ?, login_blocked_until = ?
                WHERE username = ?
            """, (failures, blocked_until, username))

def authenticate_login(username, master_password, code):
    now = int(time.time())
    if _is_login_blocked(username, now):
        return None
    if not isinstance(code, str) or not TOTP_CODE_PATTERN.fullmatch(code):
        _record_login_failure(username, now)
        return None
    result = authenticate_user(username, master_password)
    if result is None:
        _record_login_failure(username, now)
        return None
    dek, snapshot = result
    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT id, totp_nonce, totp_ciphertext FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    if (row[0], row[1], row[2]) != (
        snapshot[0], snapshot[9], snapshot[10]
    ):
        raise RuntimeError("Account changed during authentication.")
    try:
        secret = AESGCM(dek).decrypt(
            row["totp_nonce"], row["totp_ciphertext"],
            b"pm-totp-v1:" + row["id"].encode("utf-8"),
        ).decode("ascii")
        totp = pyotp.TOTP(secret)
    except (InvalidTag, ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("TOTP secret validation failed.") from exc

    current_step = now // totp.interval
    matched_step = None
    for step in (current_step + 1, current_step, current_step - 1):
        if step >= 0 and hmac.compare_digest(totp.at(step * totp.interval), code):
            matched_step = step
            break
    if matched_step is None:
        _record_login_failure(username, now)
        return None

    with closing(sqlite3.connect(DB_PATH, timeout=10.0)) as db:
        with db:
            cursor = db.execute("""
                UPDATE users
                SET totp_last_step = ?, failed_login_attempts = 0,
                    login_blocked_until = 0
                WHERE id = ? AND totp_last_step < ?
                    AND login_blocked_until <= ?
                    AND totp_nonce = ? AND totp_ciphertext = ?
            """, (
                matched_step, row["id"], matched_step, now,
                row["totp_nonce"], row["totp_ciphertext"],
            ))
            accepted = cursor.rowcount == 1

    if not accepted:
        _record_login_failure(username, now)
        return None
    if read_account_snapshot(username) != snapshot:
        raise RuntimeError("Account changed during authentication.")
    return dek, snapshot