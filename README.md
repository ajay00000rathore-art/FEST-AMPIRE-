# quantum_shield

A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Learn Flutter](https://docs.flutter.dev/get-started/learn-flutter)
- [Write your first Flutter app](https://docs.flutter.dev/get-started/codelab)
- [Flutter learning resources](https://docs.flutter.dev/reference/learning-resources)

For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.

## Testing
You can run the cryptographic unit tests using:
```bash
flutter test test/crypto_test.dart
```
These tests verify:
- Libsodium and LibOQS initialization.
- X25519 and PQC key generation.
- The Double Ratchet protocol state machine and message sequence.
