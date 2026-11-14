import getpass
import os
import sys
import signal
import shutil
import fcntl
from functools import wraps
from pathlib import Path
import subprocess
from src.vault import (VaultError, add_entry as save_entry, list_entries as get_entries, get_entry_password,
                       find_entry as search_entry, edit_entry as update_entry, remove_entry as delete_entry)
import sqlite3
from src.accounts import (
    AccountExistsError,
    authenticate_user,
    initialize_storage,
    register_user,
    check_database_integrity,
    read_account_snapshot
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
DATA_DIR = Path(__file__).resolve().parent.parent / 'data'
DB_PATH = DATA_DIR / 'users.db'
VAULT_DIR = DATA_DIR / 'vaults'

def read_bounded_line(prompt, length):
    print(prompt, end="", flush=True)
    line = sys.stdin.readline(length+2)
    if line == "":
        raise EOFError
    if len(line.rstrip("\r\n")) > length:
        while line and not line.endswith("\n"):
            line = sys.stdin.readline(4096)
        raise ValueError("Input is too long")
    return line.strip()

def copy_to_clipboard(password):
    if os.environ.get("WSL_DISTRO_NAME"):
        command = ["clip.exe"]
    elif sys.platform == "win32":
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
        stderr=subprocess.DEVNULL
    )


class PasswordManagerCLI:
    def __init__(self):
        self.current_user = None
        self.vault_key = None
        self.running = True
        self.account_snapshot = None

    def clear_session(self):
        self.vault_key = None
        self.current_user = None
        self.account_snapshot = None

    def handle_termination(self, signum, frame):
        raise SystemExit(128 + signum)

    def check_session_integrity(self):
        if self.current_user is None:
            return True
        try:
            current = read_account_snapshot(self.current_user)
        except sqlite3.Error:
            current = None
        if self.account_snapshot is None or current != self.account_snapshot:
            self.clear_session()
            print("Account database changed or unavailable. Session terminated.")
            return False
        return True

    def run(self):
        if os.name == "posix":
            for sig in (
                    signal.SIGTERM,
                    signal.SIGHUP,
                    signal.SIGQUIT,
                    signal.SIGTSTP
            ):
                signal.signal(sig, self.handle_termination)

        print('PASSWORD MANAGER')
        print("Type 'help' to see available commands")
        try:
            while self.running:
                try:
                    command = read_bounded_line('pm> ', 64).lower()
                    self.handle_command(command)
                except ValueError as exc:
                    print(exc)
                except (KeyboardInterrupt, EOFError):
                    print()
                    break
        finally:
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
            print("Unknown command. Type 'help' to see available commands")
            return
        action()

    def show_help(self):
        print(HELP_TEXT)

    def register(self):
        if self.current_user is not None:
            print("Log out before registering another user.")
            return

        username = read_bounded_line("Username: ", 32).lower()
        password = getpass.getpass("Master password: ")
        confirmation = getpass.getpass("Confirm master password: ")
        if password != confirmation:
            print("Passwords do not match.")
            return
        try:
            register_user(username, password)
        except (AccountExistsError, ValueError) as exc:
            print(f"Registration failed: {exc}")
            return
        print("Account successfully created.")
        #TOTP logic to be added

    def login(self):
        if self.current_user is not None:
            print("Already logged in. Log out first.")
            return
        username = read_bounded_line("Username: ", 32).lower()
        password = getpass.getpass("Master password: ")
        try:
            result = authenticate_user(username, password)
        except RuntimeError as exc:
            print(f"Login failed: {exc}")
            return
        if result is None:
            print("Invalid username or master password.")
            return

        dek, snapshot = result
        self.current_user = username
        self.vault_key = dek
        self.account_snapshot = snapshot
        print(f"Logged in as {username}. Vault unlocked.")

    def logout(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        self.clear_session()
        print("Logged out. Vault locked.")

    def locked_vault_write(func):
        @wraps(func)
        def wrapper(username, dek, *args, **kwargs):
            with sqlite3.connect(DB_PATH) as db:
                user = db.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (username,)
                ).fetchone()
            if user is None:
                raise VaultError("User account was not found.")
            user_id = user[0]
            lock_path = VAULT_DIR / f"{user_id}.lock"
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(lock_path, flags, 0o600)
            except OSError as exc:
                raise VaultError("Could not open vault lock file.") from exc

            with os.fdopen(fd, "r+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    return func(username, dek, *args, **kwargs)
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return wrapper

    @locked_vault_write
    def add_entry(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        if self.vault_key is None:
            print("Vault is locked. Unlock it first.")
            return

        service_name = read_bounded_line("Service name: ", 100)
        if not service_name:
            print("Service name cannot be empty.")
            return

        password = getpass.getpass("Entry password: ")
        if not 1<=len(password)<=256:
            print("Entry password must be 1-256 characters.")
            return
        confirmation = getpass.getpass("Confirm entry password: ")
        if len(confirmation) > 256:
            print("Input is too long.")
            return
        if password != confirmation:
            print("Passwords do not match.")
            return

        notes = read_bounded_line("Notes: (optional): ", 1000)

        try:
            save_entry(self.current_user, self.vault_key, service_name, password, notes)
        except (ValueError, VaultError) as exc:
            print(f"Failed to save entry: {exc}")
            return
        print("Entry saved.")

    def list_entries(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        if self.vault_key is None:
            print("Vault is locked. Unlock it first.")
            return

        try:
            services = get_entries(self.current_user, self.vault_key)
        except VaultError as exc:
            print(f"Failed to get entries: {exc}")
            return

        if not services:
            print("Vault is empty.")
            return
        print(f"Saved services ({len(services)}):")
        for index, service in enumerate(services, start=1):
            print(f"{index}. {service}")

    def copy_entry(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        if self.vault_key is None:
            print("Vault is locked. Unlock it first.")
            return

        service_name = read_bounded_line("Service name: ", 100)
        if not service_name or not service_name.strip():
            print("Service name cannot be empty.")
            return
        try:
            password = get_entry_password(
                self.current_user,
                self.vault_key,
                service_name
            )
            copy_to_clipboard(password)
        except VaultError as exc:
            print(f"Could not copy password: {exc}")
            return
        except (OSError, RuntimeError, subprocess.CalledProcessError):
            print("Failed to copy password to clipboard.")
            return

        print("Password copied to clipboard.")

    def find_entry(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        if self.vault_key is None:
            print("Vault is locked. Unlock it first.")
            return
        service_name = read_bounded_line("Service name: ", 100)
        if not service_name or not service_name.strip():
            print("Service name cannot be empty.")
            return
        try:
            entry = search_entry(self.current_user, self.vault_key, service_name)
        except VaultError as exc:
            print(f"Failed to find entry: {exc}")
            return
        print(f"Service: {entry['service_name']}")
        print(f"Notes: {entry['notes'] or '(none)'}")
        print("Password: Use 'copy' command to access password.")

    @locked_vault_write
    def edit_entry(self):
        if self.current_user is None:
            print("Please log in first.")
            return
        if self.vault_key is None:
            print("Vault is locked. Use unlock first.")
            return

        service_name = read_bounded_line("Service name to edit: ", 100)
        if not service_name or not service_name.strip():
            print("Service name cannot be empty.")
            return
        new_service_name = read_bounded_line("New service name (Enter to keep): ", 100)
        if not new_service_name: new_service_name = None

        new_password = getpass.getpass("New password (Enter to keep): ")
        if not new_password:
            new_password = None
        else:
            confirm_password = getpass.getpass("Confirm new password: ")
            if new_password != confirm_password:
                print("Passwords do not match.")
                return
        new_notes = read_bounded_line("New notes (Enter to keep, '/clear' to remove): ", 1000)
        if new_notes=="": new_notes = None
        elif new_notes == "/clear":
            new_notes = ""
        try:
            changed = update_entry(self.current_user, self.vault_key, service_name, new_service_name, new_password, new_notes)
        except (ValueError, VaultError) as exc:
            print(f"Failed to edit entry: {exc}")
            return
        if changed:
            print("Entry updated successfully.")
        else:
            print("No changes made.")

    @locked_vault_write
    def remove_entry(self):
        if self.current_user is None:
            print("Please log in first.")
            return
        if self.vault_key is None:
            print("Vault is locked. Use unlock first.")
            return

        service_name = read_bounded_line("Service name to remove: ", 100)
        if not service_name or not service_name.strip():
            print("Service name cannot be empty.")
            return
        confirmation = read_bounded_line(
            f"Are you sure you want to remove {service_name!r}? (yes/no): ",
            3
        )
        if confirmation.strip().casefold() != "yes":
            print("Removal cancelled.")
            return
        try:
            delete_entry(self.current_user, self.vault_key, service_name)
        except (VaultError, ValueError) as exc:
            print(f"Failed to remove entry: {exc}")
            return
        print("Removal successful.")

    def lock_vault(self):
        if self.current_user is None:
            print("Log in first to lock vault.")
            return
        elif self.vault_key is None:
            print("Vault is already locked.")
        else:
            self.vault_key = None
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
        except RuntimeError as exc:
            print(f"Unlock failed: {exc}")
            return
        if result is None:
            print("Invalid master password.")
            return
        dek, snapshot = result
        if snapshot != self.account_snapshot:
            self.clear_session()
            print("Account data changed. Session terminated.")
            return
        self.vault_key = dek
        print("Vault unlocked.")

    def exit_app(self):
        self.running = False


def main():
    if os.name == "posix":
        os.umask(0o077)
    try:
        initialize_storage()
        check_database_integrity()
    except (RuntimeError, sqlite3.Error) as exc:
        print(f"Startup failed: {exc}")
        return
    app = PasswordManagerCLI()
    app.run()

if __name__ == "__main__":
    main()