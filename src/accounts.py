import sqlite3
import json
import re
import os
import secrets
import uuid
from pathlib import Path
from contextlib import closing

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_DIR = Path(__file__).resolve().parent.parent / 'data'
DB_PATH = DATA_DIR / 'users.db'
VAULT_DIR = DATA_DIR / 'vaults'
USERNAME_PATTERN = re.compile(r'[a-z0-9_]{3,32}')

TIME_COST = 3
MEMORY_COST = 65536
PARALLELISM = 2
HASHER = PasswordHasher(time_cost=TIME_COST, memory_cost=MEMORY_COST, parallelism=PARALLELISM)

def check_database_integrity():
    try:
        with closing(sqlite3.connect(
            DB_PATH.as_uri() + "?mode=ro",
            uri=True
        )) as db:
            result = db.execute(
                "PRAGMA integrity_check"
            ).fetchall()

    except sqlite3.Error as exc:
        raise RuntimeError(
            "Cannot read or verify the database."
        ) from exc

    if result != [("ok",)]:
        raise RuntimeError("Database integrity check failed.")


def read_account_snapshot(username):
    with closing(sqlite3.connect(
        DB_PATH.as_uri() + "?mode=ro",
        uri=True
    )) as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    return user

class AccountExistsError(Exception):
    pass

def initialize_storage():
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)
    if os.name == 'posix':
        os.chmod(DATA_DIR, 0o700)
        os.chmod(VAULT_DIR, 0o700)
    with sqlite3.connect(DB_PATH) as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users
            (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                kek_salt BLOB NOT NULL,
                kek_time_cost INTEGER NOT NULL,
                kek_memory_cost INTEGER NOT NULL,
                kek_parallelism INTEGER NOT NULL,
                dek_nonce BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL
            )
        ''')
    if os.name == 'posix':
        os.chmod(DB_PATH, 0o600)

def derive_kek(password, salt, time_cost, memory_cost, parallelism):
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID
    )

def register_user(username, master_password):
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError('Username must be 3-32 characters: lowercase letters, digits or _')
    if not 12<=len(master_password)<=128 or master_password.isspace():
        raise ValueError('Master password must contain 12-128 characters')
    user_id = uuid.uuid4().hex
    password_hash = HASHER.hash(master_password)
    salt = secrets.token_bytes(16)
    kek = derive_kek(master_password, salt, TIME_COST, MEMORY_COST, PARALLELISM)
    dek = AESGCM.generate_key(256)
    dek_nonce = secrets.token_bytes(12)
    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, b'pm-dek-v1:' + user_id.encode())

    vault_nonce = secrets.token_bytes(12)
    vault_data = json.dumps({'version': 1, 'entries': []}).encode('utf-8')
    vault_ciphertext = AESGCM(dek).encrypt(vault_nonce, vault_data, b'pm-vault-v1:' + user_id.encode())
    vault_path = VAULT_DIR / f'{user_id}.vault'

    created_vault = False
    with sqlite3.connect(DB_PATH) as db:
        try:
            db.execute('''
                INSERT INTO users (
                    id, username, password_hash, kek_salt,
                    kek_time_cost, kek_memory_cost, kek_parallelism,
                    dek_nonce, wrapped_dek
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, username, password_hash, salt,
                TIME_COST, MEMORY_COST, PARALLELISM,
                dek_nonce, wrapped_dek,
            ))
            fd = os.open(vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created_vault = True
            with os.fdopen(fd, 'wb') as f:
                f.write(vault_nonce + vault_ciphertext)
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            if created_vault:
                vault_path.unlink(missing_ok=True)
            raise AccountExistsError('Username already exists.') from exc
        except Exception:
            db.rollback()
            if created_vault:
                vault_path.unlink(missing_ok=True)
            raise

def authenticate_user(username, master_password):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None:
            return None
        try:
            HASHER.verify(user['password_hash'], master_password)
        except VerificationError:
            return None
        except VerificationError as exc:
            raise RuntimeError('Stored password verifier is incorrect') from exc

        kek = derive_kek(master_password, user['kek_salt'], user['kek_time_cost'], user['kek_memory_cost'], user['kek_parallelism'])
        try:
            dek = AESGCM(kek).decrypt(user['dek_nonce'], user['wrapped_dek'], b'pm-dek-v1:' + user['id'].encode())
            contents = (VAULT_DIR / f"{user['id']}.vault").read_bytes()
            AESGCM(dek).decrypt(contents[:12], contents[12:], b'pm-vault-v1:' + user['id'].encode())
        except (InvalidTag, FileNotFoundError, ValueError) as exc:
            raise RuntimeError('Vailt is missing, damaged or cannot be decrypted') from exc
        return dek, tuple(user)