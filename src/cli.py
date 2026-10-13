import getpass
import sys

MAX_COMMAND_LENGTH = 64

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

class PasswordManagerCLI:
    def __init__(self):
        self.current_user = None
        self.vault_locked = True
        self.running = True

    def run(self):
        print("PASSWORD MANAGER")
        print("Type 'help' to see available commands")
        while self.running:
            try:
                print("pm> ", end="", flush=True)
                command = sys.stdin.readline(MAX_COMMAND_LENGTH + 2)
                if command == "":
                    raise EOFError
                if len(command.rstrip("\r\n")) > MAX_COMMAND_LENGTH:
                    while command and not command.endswith("\n"):
                        command = sys.stdin.readline(4096)
                    print("Command is too long")
                    continue
                self.handle_command(command.strip().lower())
            except (KeyboardInterrupt, EOFError):
                print("\nExiting Password Manager")
                self.running = False

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
        print("Registration logic to be added")

    def login(self):
        print("Login logic to be added")

    def logout(self):
        if self.current_user is None:
            print("No user is currently logged in.")
            return

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
            print("No vault is currently unlocked.")
            return
        self.vault_locked = True
        print("Vault locked.")

    def unlock_vault(self):
        if self.current_user is None:
            print("No vault is currently locked.")
            return
        self.vault_locked = False
        print ("Vault unlocked logic to be added")

    def exit_app(self):
        self.running = False
        print("Exiting Password Manager")

def main():
    app = PasswordManagerCLI()
    app.run()

if __name__ == "__main__":
    main()