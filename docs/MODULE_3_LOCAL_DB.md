# Module 3: Encrypted Local Database

## 1. Purpose
The Encrypted Local Database module is responsible for the secure persistence of message history, session ratchets, and contact metadata on the user's device. This ensures that even if the physical storage is accessed while the device is locked, the application's data remains unreadable.

## 2. Design
- **Engine:** SQLite with the SQLCipher extension for full-database AES-256 encryption.
- **Key Management:** The encryption key for the database is derived from a master secret stored in hardware-backed secure storage (Module 2).
- **Schema:**
  - `messages`: Stores sender, recipient, timestamp, and encrypted payload.
  - `sessions`: Stores serialized Double Ratchet states (root keys, chain keys, skipped keys).
  - `contacts`: Stores friend information and their public pre-key bundles.

## 3. Security Review
### What could go wrong:
- **Encryption Key Leakage:** If the database key is stored insecurely (e.g., in plaintext in SharedPreferences), the encryption is effectively useless.
- **SQL Injection:** Though less common with key-value type usage, standard SQL injection risks apply if queries are built using raw string concatenation.
- **Unencrypted Cache/Logs:** Sensitive data could leak into system logs or temporary cache files if not handled carefully.

### Mitigations:
- Database key is never stored in plaintext; it's protected by the OS keystore/keychain.
- Use parameterized queries or a robust ORM to prevent SQL injection.
- Disable verbose logging in production.

### Residual Risk:
- Vulnerabilities in the SQLCipher implementation itself.
- Forensic analysis techniques that might recover data from memory or through OS-level flaws.

## 4. Known Limitations
- Initial implementation focuses on the core schema required for 1:1 messaging.
- Large attachments (media) might require a separate secure storage strategy (e.g., encrypted file system storage) to avoid database bloating.
