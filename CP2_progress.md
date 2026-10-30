# Checkpoint 2 progress

1. Implemented a working Python CLI password manager with multi-user registration and master password authentication using
Argon2id.

2. Each user has a separate encrypted vault protected using AES-256-GCM. A random DEK encrypts the vault and is protected
by a KEK derived from the master password.

3. Implemented:

- `register`: Registering a new user (currently with username and master password only). Vault is created automatically.
- `login`: Login with username and master password (TOTP will be implemented later). Vault is unlocked after login.
- `logout`: Logout process. Vault is locked automatically after `logout`.
- `lock`: Lock vault. User is still logged in, but accessing vault is impossible.
- `unlock`: Unlock vault with master password. 
- `add`: Adding new entry (user must be logged in and vault unlocked). Service name is 1-100 characters, password is
1-256 characters, notes are optional and up to 1000 characters.
- `list`: List all service names, that are stored in vault (if user logged in and vault unlocked).
- `find`: Find entry by service name and show its name and notes (if user logged in and vault unlocked). 
- `edit`: Edit entry. Input new service name, new password and/or new notes if requested (if user logged in and vault 
unlocked). 
- `remove`: Remove entry by service name (if user logged in and vault unlocked).
- `copy`: Copy password assigned to service name into clipboard, not to print it into CLI (if user logged in and vault
unlocked).
- `exit`: Exit from application. User logged out and vault locked automatically.

4. Remaining work includes TOTP-based two-factor authentication, additional security testing, improvements to error
handling and possibly improvements to CLI.
