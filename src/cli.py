"""Interactive password manager CLI with structured security audit events."""
import getpass
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys

from src.accounts import (
    AccountExistsError,
    authenticate_user,
    check_database_integrity,
    initialize_storage,
    read_account_snapshot,
    register_user,
)
from src.audit import audit_event, setup_audit_logging
from src.vault import (
    VaultError,
    add_entry as save_entry,
    edit_entry as update_entry,
    find_entry as search_entry,
    get_entry_password,
    list_entries as get_entries,
    remove_entry as delete_entry,
)

HELP_TEXT = """
Available commands:
help - Show this help message
register - Register a new user
login - Login to your account
logout - Logout your account
add - Add a password entry
list - List all entries
copy - Copy an entry password to clipboard
find - Find password entry by service name
edit - Edit an existing entry
remove - Remove a password entry
lock - Lock the current vault
unlock - Unlock the current vault
exit - Exit the application
"""


def read_bounded_line(prompt, length):
    print(prompt, end="", flush=True)
    line = sys.stdin.readline(length + 2)
    if line == "":
        raise EOFError
    if len(line.rstrip("\r\n")) > length:
        while line and not line.endswith("\n"):
            line = sys.stdin.readline(4096)
        raise ValueError("Input is too long.")
    return line.strip()


def display_text(value):
    return json.dumps(value, ensure_ascii=True)


def copy_to_clipboard(password):
    if os.environ.get("WSL_DISTRO_NAME") or sys.platform == "win32":
        command = ["clip.exe"]
    elif sys.platform.startswith("linux"):
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
            command = ["wl-copy"]
        elif os.environ.get("DISPLAY") and shutil.which("xclip"):
            command = ["xclip", "-selection", "clipboard"]
        else:
            raise RuntimeError("No supported clipboard utility found.")
    else:
        raise RuntimeError("Unsupported operating system.")

    subprocess.run(
        command,
        input=password,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class PasswordManagerCLI:
    def __init__(self):
        self.current_user = None
        self.vault_key = None
        self.account_snapshot = None
        self.running = True
        self.exit_reason = "terminated"

    def clear_session(self):
        self.vault_key = None
        self.current_user = None
        self.account_snapshot = None

    def handle_termination(self, signum, frame):
        self.exit_reason = "terminated"
        raise SystemExit(128 + signum)

    def require_unlocked(self, event):
        if self.current_user is None:
            audit_event(event, outcome="denied", reason="not_authenticated")
            print("Please log in first.")
            return False
        if self.vault_key is None:
            audit_event(event, self.current_user, "denied", "vault_locked")
            print("Vault is locked. Use unlock first.")
            return False
        return True

    def check_session_integrity(self):
        if self.current_user is None:
            return True
        try:
            current = read_account_snapshot(self.current_user)
        except (sqlite3.Error, OSError):
            current = None

        if self.account_snapshot is None or current != self.account_snapshot:
            audit_event("integrity_failure", self.current_user, "failure", "account_changed")
            self.clear_session()
            print("Session ended due to an integrity error.")
            return False
        return True

    def run(self):
        if os.name == "posix":
            for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP):
                signal.signal(sig, self.handle_termination)

        print("PASSWORD MANAGER")
        print("Type 'help' to see available commands")
        try:
            while self.running:
                try:
                    command = read_bounded_line("pm> ", 64).lower()
                    self.handle_command(command)
                except ValueError:
                    audit_event("input_rejected", self.current_user, "denied", "invalid_input")
                    print("Invalid or oversized input.")
                except KeyboardInterrupt:
                    self.exit_reason = "interrupted"
                    print()
                    break
                except EOFError:
                    self.exit_reason = "eof"
                    print()
                    break
                except Exception:
                    audit_event("unexpected_error", self.current_user, "failure", "unexpected_error")
                    self.clear_session()
                    print("Operation failed. Session ended.")
        finally:
            if self.current_user is not None:
                audit_event("session_end", self.current_user, "success", self.exit_reason)
            self.clear_session()
            self.running = False
            print("Exiting Password Manager")

    def handle_command(self, command):
        if not command:
            return
        if self.current_user is not None and command not in ("exit", "logout"):
            if not self.check_session_integrity():
                return
        commands = {
            "help": self.show_help,
            "register": self.register,
            "login": self.login,
            "logout": self.logout,
            "add": self.add_entry,
            "list": self.list_entries,
            "find": self.find_entry,
            "copy": self.copy_entry,
            "edit": self.edit_entry,
            "remove": self.remove_entry,
            "lock": self.lock_vault,
            "unlock": self.unlock_vault,
            "exit": self.exit_app,
        }
        action = commands.get(command)
        if action is None:
            print("Unknown command. Type 'help' to see available commands.")
            return
        action()

    def show_help(self):
        print(HELP_TEXT)

    def register(self):
        if self.current_user is not None:
            audit_event("registration", self.current_user, "denied", "operation_failed")
            print("Log out before registering another user.")
            return
        username = read_bounded_line("Username: ", 32).lower()
        password = getpass.getpass("Master password: ")
        confirmation = getpass.getpass("Confirm master password: ")
        if password != confirmation:
            audit_event("registration", username, "failure", "password_mismatch")
            print("Passwords do not match.")
            return
        try:
            register_user(username, password)
        except AccountExistsError:
            audit_event("registration", username, "failure", "duplicate_username")
            print("Registration failed.")
            return
        except ValueError:
            audit_event("registration", username, "failure", "invalid_input")
            print("Registration failed: invalid input.")
            return
        except (OSError, sqlite3.Error):
            audit_event("registration", username, "failure", "storage_error")
            print("Registration failed.")
            return
        audit_event("registration", username)
        print("Account successfully created.")
        # TOTP logic to be added

    def login(self):
        if self.current_user is not None:
            print("Already logged in. Log out first.")
            return
        username = read_bounded_line("Username: ", 32).lower()
        password = getpass.getpass("Master password: ")
        try:
            result = authenticate_user(username, password)
        except (RuntimeError, sqlite3.Error, OSError):
            audit_event("login", username, "failure", "authentication_error")
            print("Login failed.")
            return
        if result is None:
            audit_event("login", username, "failure", "invalid_credentials")
            print("Invalid username or master password.")
            return

        dek, snapshot = result
        self.current_user = username
        self.vault_key = dek
        self.account_snapshot = snapshot
        audit_event("login", username)
        print(f"Logged in as {username}. Vault unlocked.")

    def logout(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        username = self.current_user
        self.clear_session()
        audit_event("logout", username)
        print("Logged out. Vault locked.")

    def add_entry(self):
        if not self.require_unlocked("entry_add"):
            return
        service_name = read_bounded_line("Service name: ", 100)
        if not service_name:
            audit_event("entry_add", self.current_user, "failure", "invalid_input")
            print("Service name cannot be empty.")
            return
        password = getpass.getpass("Entry password: ")
        if not 1 <= len(password) <= 256:
            audit_event("entry_add", self.current_user, "failure", "invalid_input")
            print("Entry password must be 1-256 characters.")
            return
        confirmation = getpass.getpass("Confirm entry password: ")
        if password != confirmation:
            audit_event("entry_add", self.current_user, "failure", "password_mismatch")
            print("Passwords do not match.")
            return
        notes = read_bounded_line("Notes (optional): ", 1000)
        try:
            save_entry(self.current_user, self.vault_key, service_name, password, notes)
        except (ValueError, VaultError):
            audit_event("entry_add", self.current_user, "failure", "operation_failed")
            print("Failed to add entry.")
            return
        audit_event("entry_add", self.current_user)
        print("Entry saved.")

    def list_entries(self):
        if not self.require_unlocked("entry_list"):
            return
        try:
            services = get_entries(self.current_user, self.vault_key)
        except VaultError:
            audit_event("entry_list", self.current_user, "failure", "operation_failed")
            print("Failed to list entries.")
            return
        audit_event("entry_list", self.current_user)
        if not services:
            print("Vault is empty.")
            return
        print(f"Saved services ({len(services)}):")
        for index, service in enumerate(services, start=1):
            print(f"{index}. {display_text(service)}")

    def find_entry(self):
        if not self.require_unlocked("entry_find"):
            return
        service_name = read_bounded_line("Service name: ", 100)
        if not service_name:
            audit_event("entry_find", self.current_user, "failure", "invalid_input")
            print("Service name cannot be empty.")
            return
        try:
            entry = search_entry(self.current_user, self.vault_key, service_name)
        except VaultError:
            audit_event("entry_find", self.current_user, "failure", "operation_failed")
            print("Entry not found or vault could not be read.")
            return
        audit_event("entry_find", self.current_user)
        print(f"Service: {display_text(entry['service_name'])}")
        print(f"Notes: {display_text(entry['notes']) if entry['notes'] else '(none)'}")
        print("Password: Use 'copy' command to access password.")

    def copy_entry(self):
        if not self.require_unlocked("entry_copy"):
            return
        service_name = read_bounded_line("Service name: ", 100)
        if not service_name:
            audit_event("entry_copy", self.current_user, "failure", "invalid_input")
            print("Service name cannot be empty.")
            return
        password = None
        try:
            password = get_entry_password(self.current_user, self.vault_key, service_name)
            copy_to_clipboard(password)
        except VaultError:
            audit_event("entry_copy", self.current_user, "failure", "operation_failed")
            print("Could not retrieve password.")
            return
        except (OSError, RuntimeError, subprocess.CalledProcessError):
            audit_event("entry_copy", self.current_user, "failure", "clipboard_unavailable")
            print("Could not copy password to clipboard.")
            return
        finally:
            password = None
        audit_event("entry_copy", self.current_user)
        print("Password copied to clipboard.")

    def edit_entry(self):
        if not self.require_unlocked("entry_edit"):
            return
        service_name = read_bounded_line("Service name to edit: ", 100)
        if not service_name:
            audit_event("entry_edit", self.current_user, "failure", "invalid_input")
            print("Service name cannot be empty.")
            return
        new_service_name = read_bounded_line("New service name (Enter to keep): ", 100) or None
        new_password = getpass.getpass("New password (Enter to keep): ") or None
        if new_password is not None:
            confirmation = getpass.getpass("Confirm new password: ")
            if new_password != confirmation:
                audit_event("entry_edit", self.current_user, "failure", "password_mismatch")
                print("Passwords do not match.")
                return
        new_notes = read_bounded_line("New notes (Enter to keep, '/clear' to remove): ", 1000)
        if new_notes == "":
            new_notes = None
        elif new_notes == "/clear":
            new_notes = ""
        try:
            changed = update_entry(
                self.current_user, self.vault_key, service_name,
                new_service_name, new_password, new_notes,
            )
        except (VaultError, ValueError):
            audit_event("entry_edit", self.current_user, "failure", "operation_failed")
            print("Failed to edit entry.")
            return
        if changed:
            audit_event("entry_edit", self.current_user)
            print("Entry updated successfully.")
        else:
            audit_event("entry_edit", self.current_user, "success", "no_changes")
            print("No changes made.")

    def remove_entry(self):
        if not self.require_unlocked("entry_remove"):
            return
        service_name = read_bounded_line("Service name to remove: ", 100)
        if not service_name:
            audit_event("entry_remove", self.current_user, "failure", "invalid_input")
            print("Service name cannot be empty.")
            return
        confirmation = read_bounded_line(
            f"Are you sure you want to remove {display_text(service_name)}? (yes/no): ", 3
        )
        if confirmation.casefold() != "yes":
            audit_event("entry_remove", self.current_user, "denied", "cancelled")
            print("Removal cancelled.")
            return
        try:
            delete_entry(self.current_user, self.vault_key, service_name)
        except (VaultError, ValueError):
            audit_event("entry_remove", self.current_user, "failure", "operation_failed")
            print("Failed to remove entry.")
            return
        audit_event("entry_remove", self.current_user)
        print("Removal successful.")

    def lock_vault(self):
        if self.current_user is None:
            print("Log in first to lock vault.")
            return
        if self.vault_key is None:
            print("Vault is already locked.")
            return
        self.vault_key = None
        audit_event("vault_lock", self.current_user)
        print("Vault locked.")

    def unlock_vault(self):
        if self.current_user is None:
            print("Log in first to unlock vault.")
            return
        if self.vault_key is not None:
            print("Vault is already unlocked.")
            return
        password = getpass.getpass("Master password: ")
        try:
            result = authenticate_user(self.current_user, password)
        except (RuntimeError, sqlite3.Error, OSError):
            audit_event("vault_unlock", self.current_user, "failure", "authentication_error")
            print("Unlock failed.")
            return
        if result is None:
            audit_event("vault_unlock", self.current_user, "failure", "invalid_credentials")
            print("Invalid master password.")
            return
        dek, snapshot = result
        if snapshot != self.account_snapshot:
            audit_event("integrity_failure", self.current_user, "failure", "account_changed")
            self.clear_session()
            print("Session ended due to an integrity error.")
            return
        self.vault_key = dek
        audit_event("vault_unlock", self.current_user)
        print("Vault unlocked.")

    def exit_app(self):
        self.exit_reason = "terminated"
        self.running = False


def main():
    if os.name == "posix":
        os.umask(0o077)
    try:
        initialize_storage()
        setup_audit_logging()
    except (OSError, RuntimeError, sqlite3.Error):
        # Auditing may not be available yet.
        print("Application initialization failed.")
        return
    try:
        check_database_integrity()
    except (OSError, RuntimeError, sqlite3.Error):
        audit_event("integrity_failure", outcome="failure", reason="database_check_failed")
        print("Application initialization failed.")
        return
    app = PasswordManagerCLI()
    app.run()


if __name__ == "__main__":
    main()
