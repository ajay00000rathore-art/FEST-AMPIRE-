import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class HKDF {
  static Uint8List compute({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int length,
  }) {
    // HKDF-Extract
    final hmacExtract = Hmac(sha256, salt.isEmpty ? Uint8List(32) : salt);
    final prk = hmacExtract.convert(ikm).bytes;

    // HKDF-Expand
    final hmacExpand = Hmac(sha256, prk);
    final result = Uint8List(length);
    var generated = 0;
    var counter = 1;
    var lastT = <int>[];

    while (generated < length) {
      final message = Uint8List.fromList([...lastT, ...info, counter]);
      lastT = hmacExpand.convert(message).bytes;
      final remaining = length - generated;
      final toCopy = lastT.length < remaining ? lastT.length : remaining;
      result.setRange(generated, generated + toCopy, lastT);
      generated += toCopy;
      counter++;
    }
    return result;
  }
}
