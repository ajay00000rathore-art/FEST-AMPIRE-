import 'dart:typed_data';
import 'package:sodium/sodium.dart';
import 'sodium_init.dart';
import 'hkdf.dart';

class HybridKeyExchange {
  static Future<Uint8List> computeSharedSecret({
    required SecureKey x25519SharedSecret,
    required List<int> mlKemSharedSecret,
    required Uint8List salt,
    required Uint8List info,
  }) async {
    final x25519Bytes = await x25519SharedSecret.extractBytes();
    final combinedSecret = Uint8List(x25519Bytes.length + mlKemSharedSecret.length);
    combinedSecret.setRange(0, x25519Bytes.length, x25519Bytes);
    combinedSecret.setRange(x25519Bytes.length, combinedSecret.length, mlKemSharedSecret);

    final result = HKDF.compute(
      ikm: combinedSecret,
      salt: salt,
      info: info,
      length: 32,
    );

    combinedSecret.fillRange(0, combinedSecret.length, 0);
    x25519Bytes.fillRange(0, x25519Bytes.length, 0);

    return result;
  }
}
