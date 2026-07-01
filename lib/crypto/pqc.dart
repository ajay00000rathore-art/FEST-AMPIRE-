import 'package:oqs/oqs.dart';

class PQCService {
  static bool _initialized = false;

  static void _ensureInitialized() {
    if (!_initialized) {
      try {
        LibOQS.init();
        _initialized = true;
      } catch (e) {
        throw PQCException('Failed to initialize liboqs: $e');
      }
    }
  }

  static MyKEMKeyPair generateMLKEM768KeyPair() {
    _ensureInitialized();
    final kem = KEM.create('ML-KEM-768');
    if (kem == null) throw PQCException('ML-KEM-768 not supported by liboqs');
    try {
      final keyPair = kem.generateKeyPair();
      return MyKEMKeyPair(keyPair.publicKey, keyPair.secretKey);
    } finally {
      kem.dispose();
    }
  }

  static MySigKeyPair generateMLDSA65KeyPair() {
    _ensureInitialized();
    final sig = Signature.create('ML-DSA-65');
    if (sig == null) throw PQCException('ML-DSA-65 not supported by liboqs');
    try {
      final keyPair = sig.generateKeyPair();
      return MySigKeyPair(keyPair.publicKey, keyPair.secretKey);
    } finally {
      sig.dispose();
    }
  }
}

class PQCException implements Exception {
  final String message;
  PQCException(this.message);
  @override
  String toString() => 'PQCException: $message';
}

class MyKEMKeyPair {
  final List<int> publicKey;
  final List<int> secretKey;
  MyKEMKeyPair(this.publicKey, this.secretKey);
}

class MySigKeyPair {
  final List<int> publicKey;
  final List<int> secretKey;
  MySigKeyPair(this.publicKey, this.secretKey);
}
