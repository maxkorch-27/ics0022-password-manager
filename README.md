# ics0022-password-manager
## Scope

This project is a local, multi-user command-line password manager developed
for the Secure Programming course.

The application will allow multiple users to create accounts and securely
store and manage their passwords on the same computer. Each user will have
their own separate password vault, which can only be accessed after successful
authentication.

Each user account will have:

- A unique username
- A master password
- Mandatory two-factor authentication (TOTP)
- A separate encrypted password vault

Each vault entry will contain:

- `id`
- `service_name`
- `password`
- `notes`

The master password will be selected during account creation and cannot be
changed. The user will be informed about this limitation before creating the account.

The main security goal is to ensure that users can only access their own vault
and that stored passwords remain protected both when stored on disk and while
being transferred between the application's components.

## Planned Commands

The application will provide a command-line interface with the following
commands:

| Command | Description |
|---|---|
| `register` | Create a new user account and configure TOTP-based 2FA |
| `login` | Authenticate a user using their username, master password, and TOTP code |
| `logout` | End the current user session |
| `lock` | Lock the currently unlocked vault |
|`unlock`| Unlock the currently locked vault |
| `add` | Add a new password entry |
| `edit` | Edit an existing password entry |
| `remove` | Remove a password entry |
| `list` | List the user's stored password entries |
| `find` | Find a specific password entry |
 |`copy`| Copy the service password into clipboard |

Passwords will be entered using hidden terminal input and will not be provided
as command-line arguments.

## Build and Run

### Requirements

- Python 3.12 or newer
- pip
- Git

### Installation

1. Clone the repository and enter the project directory

2. Create and activate a virtual environment

3. Install the required dependencies from `requirements.txt` file

### Running the Application

Run the password manager with:

```bash
python -m src
```

The application runs locally in the terminal and does not require a network
connection or external server.
