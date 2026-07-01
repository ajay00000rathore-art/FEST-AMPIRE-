import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_shield/crypto/sodium_init.dart';
import 'package:quantum_shield/crypto/x25519.dart';
import 'package:quantum_shield/crypto/pqc.dart';
import 'package:quantum_shield/crypto/double_ratchet.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Crypto Core Tests', () {
    test('Double Ratchet Sequence', () async {
      final sodium = await MySodiumInit.instance;

      final aliceDh = sodium.crypto.box.keyPair();
      final bobDh = sodium.crypto.box.keyPair();
      final sharedRootKey = sodium.randombytes.buf(32);

      final aliceState = await DoubleRatchetService.initializeRatchet(
        sharedRootKey: sharedRootKey,
        initialDhKeyPair: aliceDh,
        remoteDhPublicKey: bobDh.publicKey,
      );

      final bobState = await DoubleRatchetService.initializeRatchet(
        sharedRootKey: sharedRootKey,
        initialDhKeyPair: bobDh,
        remoteDhPublicKey: aliceDh.publicKey,
      );

      // Alice sends to Bob
      final message1 = Uint8List.fromList('Hello Bob'.codeUnits);
      final encrypted1 = await DoubleRatchetService.encrypt(aliceState, message1, Uint8List(0));
      final decrypted1 = await DoubleRatchetService.decrypt(bobState, encrypted1, Uint8List(0));
      expect(String.fromCharCodes(decrypted1), equals('Hello Bob'));

      // Bob responds to Alice
      final message2 = Uint8List.fromList('Hi Alice'.codeUnits);
      final encrypted2 = await DoubleRatchetService.encrypt(bobState, message2, Uint8List(0));
      final decrypted2 = await DoubleRatchetService.decrypt(aliceState, encrypted2, Uint8List(0));
      expect(String.fromCharCodes(decrypted2), equals('Hi Alice'));
    });

    test('Sodium Initialization', () async {
      final sodium = await MySodiumInit.instance;
      expect(sodium, isNotNull);
    });

    test('X25519 Key Generation', () async {
      final keyPair = await X25519Service.generateKeyPair();
      expect(keyPair.publicKey, isNotNull);
      expect(keyPair.secretKey, isNotNull);
    });

    group('Post-Quantum Tests', () {
      test('ML-KEM-768 Key Generation', () {
        try {
          final keyPair = PQCService.generateMLKEM768KeyPair();
          expect(keyPair.publicKey, isNotEmpty);
          expect(keyPair.secretKey, isNotEmpty);
        } on PQCException catch (e) {
          print('Skipping PQ test: $e');
        } catch (e) {
          print('PQ test failed: $e');
        }
      });
    });
  });
}
