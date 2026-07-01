import 'package:sodium/sodium.dart';
import 'sodium_init.dart';

class X25519Service {
  static Future<KeyPair> generateKeyPair() async {
    final sodium = await MySodiumInit.instance;
    return sodium.crypto.box.keyPair();
  }
}
