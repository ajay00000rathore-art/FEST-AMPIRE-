# Module 2: Hardware-backed Key Storage Adapters

## 1. Purpose
The Key Storage module provides a secure mechanism for storing long-term private keys (Identity Keys, Signed Pre-keys, and PQ Pre-keys) in hardware-backed secure storage. This ensures that even if the device's main application processor is compromised, the private keys cannot be extracted.

## 2. Design
- **Interface-based approach:** A common Dart interface `KeyStorageInterface` will be used by the application.
- **Platform Adapters:**
  - **Android:** Uses the Android Keystore system.
  - **iOS/macOS:** Uses the Secure Enclave via Keychain Services.
  - **Linux:** Uses the TPM or Secret Service API (libsecret).
  - **Windows:** Uses the TPM via Cryptography API: Next Generation (CNG).
- **Non-exportability:** Keys generated within the hardware module must be marked as non-exportable whenever the hardware allows.

## 3. Security Review
### What could go wrong:
- **Fallback to software storage:** If hardware storage is unavailable, sensitive keys might be stored in regular flash memory.
- **Insecure Key Wrapping:** If hardware only supports wrapping, the wrapper key's security becomes the bottleneck.
- **Access Control:** Malicious apps on the same device could potentially attempt to use the keys if the OS doesn't enforce strict application sandboxing.

### Mitigations:
- Strict requirement for hardware-backed storage for long-term keys.
- Biometric or device-passcode-backed access controls where appropriate.
- Use of the OS's strongest isolation mechanisms (StrongBox, Secure Enclave).

### Residual Risk:
- Exploits targeting the TEE (Trusted Execution Environment) or Secure Enclave itself.
- Brute-forcing of the device passcode if it's the only gate for key access.

## 4. Known Limitations
- The initial implementation may focus on common mobile platforms (Android/iOS).
- Some desktop environments might lack a TPM or a consistent API for hardware-backed storage.
- PQ keys (ML-KEM/ML-DSA) are significantly larger than classical keys and might not be supported directly as "native" key types in all hardware modules yet. In such cases, the hardware will be used to protect a classical wrapping key that encrypts the PQ keys stored in the encrypted local database.
