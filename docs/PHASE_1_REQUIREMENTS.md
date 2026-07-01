# Phase 1: Requirements and Threat Model

## 1. Project Overview
QuantumShield Messenger is a privacy-first, post-quantum-ready, end-to-end encrypted messenger for a closed 100-user deployment.

## 2. Requirements
- Hybrid X25519 + ML-KEM-768 key exchange.
- ML-DSA-65 signatures for authentication.
- Double Ratchet protocol with PQ-adapted DH step.
- Hardware-backed secure storage for private keys.
- No plaintext or private key access for the relay server.
- Support for 1:1 and group chats.

## 3. Threat Model
- **Compromised Relay Server:** The relay server is assumed to be untrusted. It should not be able to decrypt messages or gain access to long-term keys.
- **Quantum Adversary:** Messages must be protected against future quantum computers capable of breaking classical asymmetric crypto.
- **Device Theft:** Private keys must be stored in secure hardware to prevent extraction even if the device is physically compromised.
- **Metadata Minimization:** Only essential metadata for routing and delivery should be handled by the relay.
