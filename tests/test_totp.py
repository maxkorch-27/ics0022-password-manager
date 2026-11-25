"""TOTP correctness, authentication gating, expiry, replay and lockout."""
import sqlite3

import pyotp
import pytest
from src import accounts
from conftest import TEST_TIME


def code_for(account, epoch=TEST_TIME):
    return pyotp.TOTP(account.totp_secret).at(epoch)


def test_correct_master_password_and_totp_succeed(alice, freeze_account_time):
    freeze_account_time()
    result = accounts.authenticate_login("alice", alice.master_password, code_for(alice))
    assert result is not None
    assert result[0] == alice.dek
    assert result[1] == alice.snapshot


@pytest.mark.parametrize("invalid_code", ["", "12345", "1234567", "abcdef", "１２３４５６", "123 456"])
def test_invalid_totp_code_format_rejected(alice, freeze_account_time, invalid_code):
    freeze_account_time()
    assert accounts.authenticate_login("alice", alice.master_password, invalid_code) is None


def test_wrong_master_password_rejected_even_with_valid_totp(alice, freeze_account_time):
    freeze_account_time()
    assert accounts.authenticate_login("alice", "incorrect-master", code_for(alice)) is None


def test_wrong_totp_rejected_even_with_correct_master(alice, freeze_account_time):
    freeze_account_time()
    correct = code_for(alice)
    incorrect = "000000" if correct != "000000" else "999999"
    assert accounts.authenticate_login("alice", alice.master_password, incorrect) is None


def test_replayed_totp_step_cannot_be_used_twice(alice, freeze_account_time):
    freeze_account_time()
    code = code_for(alice)
    assert accounts.authenticate_login("alice", alice.master_password, code) is not None
    assert accounts.authenticate_login("alice", alice.master_password, code) is None


def test_old_totp_code_expires(alice, freeze_account_time):
    freeze_account_time()
    old_code = code_for(alice, TEST_TIME - 120)
    assert accounts.authenticate_login("alice", alice.master_password, old_code) is None


def test_adjacent_step_allowed_for_clock_skew(alice, freeze_account_time):
    freeze_account_time()
    assert accounts.authenticate_login("alice", alice.master_password,
                                       code_for(alice, TEST_TIME - 30)) is not None


def test_three_failures_trigger_temporary_cooldown(alice, freeze_account_time):
    freeze_account_time()
    for _ in range(accounts.MAX_FAILED_LOGINS):
        assert accounts.authenticate_login("alice", alice.master_password, "invalid") is None
    with sqlite3.connect(accounts.DB_PATH) as db:
        fails, blocked_until = db.execute(
            "SELECT failed_login_attempts, login_blocked_until FROM users WHERE username='alice'"
        ).fetchone()
    assert fails == accounts.MAX_FAILED_LOGINS
    assert blocked_until == TEST_TIME + accounts.LOGIN_COOLDOWN_SECONDS
    assert accounts.authenticate_login("alice", alice.master_password, code_for(alice)) is None
    freeze_account_time(TEST_TIME + accounts.LOGIN_COOLDOWN_SECONDS + 1)
    assert accounts.authenticate_login("alice", alice.master_password,
                                       code_for(alice, TEST_TIME + accounts.LOGIN_COOLDOWN_SECONDS + 1)) is not None


def test_totp_secret_is_encrypted_at_rest(alice):
    with sqlite3.connect(accounts.DB_PATH) as db:
        nonce, ciphertext = db.execute(
            "SELECT totp_nonce, totp_ciphertext FROM users WHERE username='alice'"
        ).fetchone()
    assert len(nonce) == 12
    assert len(ciphertext) > len(alice.totp_secret)
    assert alice.totp_secret.encode() not in ciphertext
    assert alice.totp_secret.encode() not in accounts.DB_PATH.read_bytes()


def test_invalid_totp_enrollment_secret_rejected(isolated_environment):
    with pytest.raises(ValueError, match="TOTP"):
        accounts.register_user("alice", "VeryStrongSecret123", "not-base32")
    assert not accounts.username_exists("alice")


def test_replay_blocked_across_distinct_instances(alice, freeze_account_time):
    freeze_account_time()
    code = code_for(alice)
    first_login = accounts.authenticate_login("alice", alice.master_password, code)
    second_login = accounts.authenticate_login("alice", alice.master_password, code)
    assert first_login is not None
    assert second_login is None
