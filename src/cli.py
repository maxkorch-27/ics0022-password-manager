import getpass
import sys
from src.accounts import AccountExistsError, authenticate_user, initialize_storage, register_user

HELP_TEXT = """
Available commands:
help - Show this help message
register - Register a new user
login - Login to your account
logout - Logout your account
add - Add a password entry
list - List all entries
find - Find password entry by service name
edit - Edit an existing entry
remove - Remove a password entry
lock - Lock the current vault
unlock - Unlock the current vault
exit - Exit the application
"""

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


class PasswordManagerCLI:
    def __init__(self):
        self.current_user = None
        self.vault_key = None
        self.running = True

    def run(self):
        print('PASSWORD MANAGER')
        print("Type 'help' to see available commands")
        while self.running:
            try:
                command = read_bounded_line('pm> ', 64).lower()
                self.handle_command(command)
            except ValueError as exc:
                print(exc)
            except (KeyboardInterrupt, EOFError):
                print()
                self.exit_app()

    def handle_command(self, command):
        if not command:
            return
        commands = {
            "help": self.show_help,
            "register": self.register,
            "login": self.login,
            "logout": self.logout,
            "add": self.add_entry,
            "list": self.list_entries,
            "find": self.find_entry,
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
            dek = authenticate_user(username, password)
        except RuntimeError as exc:
            print(f"Login failed: {exc}")
            return
        if dek is None:
            print("Invalid username or master password.")
            return

        self.current_user = username
        self.vault_key = dek
        print(f"Logged in as {username}. Vault unlocked.")

    def logout(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return
        self.vault_key = None
        self.current_user = None
        print("Logged out. Vault locked.")

        self.current_user = None
        print("Logged out.")

    def add_entry(self):
        print ("Adding logic to be added")

    def list_entries(self):
        print("List entries logic to be added")

    def find_entry(self):
        print("Find logic to be added")

    def edit_entry(self):
        print("Editing logic to be added")

    def remove_entry(self):
        print("Removing logic to be added")

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
            dek = authenticate_user(self.current_user, password)
        except RuntimeError as exc:
            print("Unlock failed: {exc}")
            return
        if dek is None:
            print("Invalid master password.")
            return
        self.vault_key = dek
        print("Vault unlocked.")

    def exit_app(self):
        self.vault_key = None
        self.current_user = None
        self.running = False
        print("Exiting Password Manager")

def main():
    initialize_storage()
    app = PasswordManagerCLI()
    app.run()

if __name__ == "__main__":
    main()