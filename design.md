# Password Manager: Design Document
## 1. Architecture

The password manager is a local, multi-user command-line application. It is
divided into the following components:

| Component | Responsibility |
|---|---|
| CLI Interface | Accepts commands and user input |
| User Management / Authentication | User registration, master password verification, TOTP authentication and session management |
| Vault Manager | Adding, editing, removing, listing and finding vault entries |
| Encryption Module | Password-based key derivation, key management, encryption and decryption |
| Storage Layer | Stores account data in SQLite and encrypted vaults on disk |
| Logging Module | Records security and audit events without storing sensitive information |

The main data flow is:

**CLI → User Management → Vault Manager → Encryption → Storage**

The Logging Module receives relevant security events from the other
components.

### Authentication and Vault Access Flow

1. The user enters a command through the CLI.
2. During login, the User Management module retrieves the user's account data
   from SQLite.
3. The master password is verified using the stored password hash.
4. The TOTP code is verified.
5. After successful authentication, the user's vault can be unlocked.
6. The Vault Manager performs operations on the authenticated user's vault.
7. The Encryption Module decrypts the vault when User is authenticated and encrypts it again when changes are saved.
8. The Storage Layer stores the encrypted vault and account information.

The application determines the vault from the authenticated user's identity.
Users cannot select an arbitrary vault belonging to another user.

---

## 2. Authentication and Key Management

Each user has:
- A unique username
- A master password
- Mandatory TOTP-based two-factor authentication
- A separate encrypted vault

### Master Password Verification

During registration, the master password is processed using Argon2id to
generate a password verifier. The verifier, salt and required parameters are
stored in the SQLite database.

During login, the entered password is processed using the same parameters and
compared with the stored verifier.

### Vault Key Management

A separate key is derived from the master password using Argon2id. This key is
called the **Key Encryption Key (KEK)**.

During account creation, the application generates a random **Data Encryption
Key (DEK)** for the user's vault.

The DEK is used to encrypt the vault with AES-256-GCM. The DEK itself is stored
only in encrypted form and is protected using the KEK.

Overall Vault decryption flow:

**Master password → Argon2id → KEK → encrypted DEK → DEK → AES-256-GCM → vault**

The master password cannot be changed in the initial version of the
application.

### Two-Factor Authentication

The application uses **Time-based One-Time Password (TOTP)** as the second
authentication factor.

**During registration:**

1. The application generates a random TOTP secret.
2. A standard TOTP provisioning URI is generated.
3. The provisioning information is displayed as a QR code in the CLI.
4. The user scans the QR code with an authenticator application.
5. The user enters the generated six-digit TOTP code.
6. The application verifies the code before completing registration.

---

## 3. Vault Format and Cryptography
Each user has a separate encrypted vault.

A vault entry contains the following fields:

| Field | Description |
|---|---|
| `id` | Unique identifier of the entry |
| `service_name` | Name of the service |
| `password` | Stored password |
| `notes` | Optional notes about the entry |
This plaintext data exists only in memory while the vault is unlocked. It is
never stored directly on disk. The stored vault will contain encrypted data together with the metadata
required for decryption, such as the format version and encryption nonce.

### Cryptographic Scheme
| Purpose | Algorithm |
|---|--------|
| Password verification | Argon2id |
| Key derivation | Argon2id |
| Vault encryption | AES-256-GCM |
| Vault encryption key | Random 256-bit DEK |
| Protection of DEK | KEK derived from master password |
| Second authentication factor | TOTP   |
| Random values | secrets|

---

## 4. Threat Model
### 4.1 Master Password

| Threat | Mitigation                       |
|---|----------------------------------|
| Brute-force or dictionary attacks | Argon2id for password hashing and key derivation |
| Weak user-selected password | Require a sufficiently strong master password |
| Password exposed through terminal input | Hidden input                     |
| Password exposed through command history | Never accept the master password as a command-line argument |
| Password stored in plaintext | Store only an Argon2id-derived password verifier |

### 4.2 Vault at Rest

| Threat | Mitigation |
|---|---|
| Attacker obtains the vault file | Encrypt vault contents using AES-256-GCM |
| Offline password guessing | Use Argon2id for password-based key derivation |
| Modification of encrypted vault | AES-256-GCM authentication tag detects tampering |
| Reuse of encryption nonce | Generate a new nonce for every encryption operation |
| Direct access to the DEK | Store the DEK only in encrypted form |

### 4.3 Vault in Memory

| Threat | Mitigation |
|-|---|
| Passwords exposed while the vault is unlocked | Keep plaintext data in memory only while required |
| Secrets accidentally written to logs | Never log vault contents or passwords |
| Password displayed unnecessarily | Hide passwords by default and require explicit action to reveal them |
| Memory inspection by a privileged local attacker | Minimize the lifetime of sensitive data in memory |

### 4.4 Interface

| Threat | Mitigation |
|---|---|
| Passwords exposed through command-line arguments | Use hidden interactive input |
| SQL injection | Use parameterized SQLite queries |
| Command injection | Do not execute user input as shell commands |
| Malformed or unexpected input | Validate user input |
| Unauthorized vault selection | Determine the vault from the authenticated user |
| Sensitive information displayed accidentally | Hide passwords by default and avoid logging secrets |

### 4.5 User Isolation

The application supports multiple users on the same computer. A user must not
be able to access another user's vault.

The authenticated user identity is maintained by the session. The Vault
Manager uses this identity to select the corresponding vault.

---

## 5. Logging
**Events that may be logged include:**
- Successful login
- Failed login
- Failed TOTP verification
- Logout
- Vault entry creation
- Vault entry modification
- Vault entry deletion

**The following information must never be written to logs:**

- Master passwords
- Vault passwords
- TOTP codes
- TOTP secrets
- KEK
- DEK
- Decrypted vault contents

---