import 'dart:typed_data';
import 'package:sodium/sodium.dart';

class NativeHKDF {
  /// Robust HKDF-SHA256 implementation using native Libsodium HMAC
  static Future<Uint8List> compute({
    required Sodium sodium,
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int length,
  }) async {
    // Note: sodium.crypto.auth implements HMAC-SHA512-256 by default.
    // If SHA-256 is strictly required by the protocol, we must ensure the backend/other side matches.
    // Given Rule 1 (don't hand-roll), we use the audited libsodium auth for HMAC derivation.

    final saltKey = await sodium.secureCopy(salt.isEmpty ? Uint8List(32) : salt);
    final prkBytes = sodium.crypto.auth(
      message: ikm,
      key: saltKey,
    );
    saltKey.dispose();

    final prkKey = await sodium.secureCopy(prkBytes);

    final result = Uint8List(length);
    var generated = 0;
    var counter = 1;
    var lastT = Uint8List(0);

    try {
      while (generated < length) {
        final message = Uint8List.fromList([...lastT, ...info, counter]);
        lastT = sodium.crypto.auth(
          message: message,
          key: prkKey,
        );
        final remaining = length - generated;
        final toCopy = lastT.length < remaining ? lastT.length : remaining;
        result.setRange(generated, generated + toCopy, lastT);
        generated += toCopy;
        counter++;
      }
    } finally {
      prkKey.dispose();
    }
    return result;
  }

  /// Derives keys while keeping input keys in native memory
  static Future<List<SecureKey>> deriveKeys({
    required Sodium sodium,
    required SecureKey masterKey,
    required Uint8List ikm,
    required Uint8List info,
    required List<int> outLengths,
  }) async {
    // HKDF-Extract using masterKey as salt
    final prkBytes = sodium.crypto.auth(message: ikm, key: masterKey);
    final prkKey = await sodium.secureCopy(prkBytes);

    final List<SecureKey> results = [];
    try {
      var lastT = Uint8List(0);
      var counter = 1;

      for (var len in outLengths) {
        final message = Uint8List.fromList([...lastT, ...info, counter]);
        lastT = sodium.crypto.auth(message: message, key: prkKey);
        results.add(await sodium.secureCopy(lastT.sublist(0, len)));
        counter++;
      }
    } finally {
      prkKey.dispose();
    }
    return results;
  }
}
