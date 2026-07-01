# Phase 2: Architecture and Protocol Specification

## 1. Cryptographic Primitives
- **KEM:** ML-KEM-768 (Kyber)
- **Signature:** ML-DSA-65 (Dilithium)
- **Classical ECDH:** X25519
- **Hash/KDF:** SHA-256 / HKDF
- **AEAD:** AES-256-GCM or ChaCha20-Poly1305 (via libsodium)

## 2. Hybrid Key Exchange
Initial handshake combines X25519 and ML-KEM-768 to provide both classical and post-quantum security.
`SharedSecret = HKDF(X25519_SS || ML-KEM_SS)`

## 3. PQ-Enabled Double Ratchet
The standard Double Ratchet protocol is enhanced by including a PQ-KEM exchange in the DH ratchet step to ensure forward secrecy against quantum attackers.

## 4. Key Storage
Keys are stored in:
- Android: Keystore System
- iOS/macOS: Secure Enclave
- Linux: TPM / Keyring fallback

## 5. Relay Server Architecture
- **Auth Service:** Minimal authentication.
- **Directory Service:** Stores public pre-key bundles (Identity Key, Signed Pre-key, PQ Pre-keys).
- **Relay Service:** WebSocket-based message delivery with Redis-backed queueing.
