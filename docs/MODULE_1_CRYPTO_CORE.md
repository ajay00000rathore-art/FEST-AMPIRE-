# Module 1: Crypto Core

## 1. Purpose
The Crypto Core module is responsible for all low-level cryptographic operations in QuantumShield Messenger. This includes key generation, hybrid key exchange, signatures, and the Double Ratchet protocol logic. Its primary goal is to provide a post-quantum secure foundation for end-to-end encryption.

## 2. Design
The module uses a hybrid approach:
- **Classical:** X25519 for Diffie-Hellman, Ed25519 or similar for classical signatures (though we prioritize ML-DSA).
- **Post-Quantum:** ML-KEM-768 for key encapsulation and ML-DSA-65 for signatures.
- **Double Ratchet:** Standard Double Ratchet protocol using DH ratchet steps (X25519) and symmetric-key chain ratchets. The symmetric encryption uses ChaCha20-Poly1305.
- **Hybrid Key Exchange:** Combines X25519 and ML-KEM-768 using HKDF-SHA256: `SharedSecret = HKDF(X25519_SS || ML-KEM_SS)`.
- **FFI Bindings:** Dart FFI is used to call into `libsodium` (classical) and `liboqs` (post-quantum).

## 3. Security Review
### What could go wrong:
- **Side-channel attacks:** Native implementations must be constant-time.
- **Key leakage:** Private keys must never leave hardware-backed storage (to be addressed in Module 2). Current PQC implementation handles keys in Dart memory, which is a known residual risk.
- **Weak Randomness:** Uses cryptographically secure random number generators provided by libsodium.

### Mitigations:
- Using audited libraries (libsodium, liboqs).
- Hybrid design ensures that even if one algorithm is broken (e.g., classical by a quantum computer), the other still provides security.
- Double Ratchet provides forward secrecy and post-compromise security.

### Residual Risk:
- Implementation bugs in the protocol logic (Ratchet state transitions).
- PQC secret keys are currently handled in raw byte lists in Dart memory.

## 4. Known Limitations
- PQC secret key memory protection: Currently, PQC keys are stored in `List<int>` (Dart heap), unlike classical keys which use `SecureKey`. This will be improved in future iterations.
- Double Ratchet implementation currently uses classical DH only for the DH-ratchet step; adding PQ-KEM to the DH step is planned for Phase 3.
