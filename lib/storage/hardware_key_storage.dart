import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'key_storage_interface.dart';

class HardwareKeyStorage implements KeyStorageInterface {
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(
      // Ensure we use the strongest isolation available
      keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
      storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
    ),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );

  @override
  Future<void> storePrivateKey(String alias, Uint8List keyBytes) async {
    final base64Key = base64Encode(keyBytes);
    await _storage.write(key: alias, value: base64Key);
    // Security: wipe keyBytes after storage
    keyBytes.fillRange(0, keyBytes.length, 0);
  }

  @override
  Future<bool> hasKey(String alias) async {
    return await _storage.containsKey(key: alias);
  }

  @override
  Future<void> deleteKey(String alias) async {
    await _storage.delete(key: alias);
  }

  @override
  Future<String?> getKeyHandle(String alias) async {
    // In this simplified adapter, we still return the key material as a "handle"
    // because full non-exportable key handles require custom platform-channel code
    // not available in standard generic storage plugins.
    return await _storage.read(key: alias);
  }
}
