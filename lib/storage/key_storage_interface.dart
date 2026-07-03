import 'dart:typed_data';

abstract class KeyStorageInterface {
  /// Stores a private key securely.
  /// Alias should be a unique identifier for the key.
  Future<void> storePrivateKey(String alias, Uint8List keyBytes);

  /// Checks if a key exists for the given alias.
  Future<bool> hasKey(String alias);

  /// Deletes a key from secure storage.
  Future<void> deleteKey(String alias);

  /// Returns a handle to the key for use in cryptographic operations.
  /// For true hardware-backed security, the raw key material should never
  /// leave the secure enclave. This handle represents that key.
  Future<String?> getKeyHandle(String alias);
}
