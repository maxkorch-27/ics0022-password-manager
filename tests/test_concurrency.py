"""Simultaneous writers must preserve all changes and uniqueness."""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from src import accounts, vault


@pytest.mark.skipif(os.name != "posix", reason="fcntl advisory locks require POSIX/WSL")
def test_parallel_additions_preserve_every_entry(alice):
    def worker(i):
        return vault.add_entry("alice", alice.dek, f"service-{i:02}", f"password-{i}", "")

    with ThreadPoolExecutor(max_workers=8) as pool:
        entry_ids = list(pool.map(worker, range(16)))
    assert len(set(entry_ids)) == 16
    assert vault.list_entries("alice", alice.dek) == [f"service-{i:02}" for i in range(16)]
    assert vault.get_entry_password("alice", alice.dek, "service-15") == "password-15"
    lock_path = accounts.VAULT_DIR / f"{alice.snapshot[0]}.lock"
    assert lock_path.exists()
    assert lock_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="fcntl advisory locks require POSIX/WSL")
def test_parallel_duplicate_add_allows_only_one(alice):
    def worker(_):
        try:
            vault.add_entry("alice", alice.dek, "same-service", "password", "")
            return "success"
        except vault.VaultError:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, range(2)))
    assert sorted(outcomes) == ["duplicate", "success"]
    assert vault.list_entries("alice", alice.dek) == ["same-service"]
