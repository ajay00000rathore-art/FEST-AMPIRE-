import 'dart:typed_data';
import 'package:sodium/sodium.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:oqs/oqs.dart';
import 'sodium_init.dart';
import 'pqc.dart';
import 'hkdf.dart';

class RatchetState {
  SecureKey rootKey;
  SecureKey? sendingChainKey;
  SecureKey? receivingChainKey;
  KeyPair dhKeyPair;
  Uint8List remoteDhPublicKey;

  MyKEMKeyPair? localMLKEMKeyPair;
  Uint8List? remoteMLKEMPublicKey;
  MySigKeyPair? localMLDSAKeyPair;
  Uint8List? remoteMLDSAPublicKey;

  int nSending = 0;
  int nReceiving = 0;
  int pn = 0;
  Map<String, SecureKey> skippedMessageKeys = {};

  RatchetState({
    required this.rootKey,
    this.sendingChainKey,
    this.receivingChainKey,
    required this.dhKeyPair,
    required this.remoteDhPublicKey,
    this.localMLKEMKeyPair,
    this.remoteMLKEMPublicKey,
    this.localMLDSAKeyPair,
    this.remoteMLDSAPublicKey,
  });

  void dispose() {
    rootKey.dispose();
    sendingChainKey?.dispose();
    receivingChainKey?.dispose();
    dhKeyPair.secretKey.dispose();
    for (var key in skippedMessageKeys.values) {
      key.dispose();
    }
  }
}

class DoubleRatchetService {
  static const int maxSkip = 1000;

  static Future<RatchetState> initializeRatchet({
    required Uint8List sharedRootKey,
    required KeyPair initialDhKeyPair,
    required Uint8List remoteDhPublicKey,
    MyKEMKeyPair? initialMLKEMKeyPair,
    Uint8List? remoteMLKEMPublicKey,
  }) async {
    final sodium = await MySodiumInit.instance;
    return RatchetState(
      rootKey: await sodium.secureCopy(sharedRootKey),
      dhKeyPair: initialDhKeyPair,
      remoteDhPublicKey: remoteDhPublicKey,
      localMLKEMKeyPair: initialMLKEMKeyPair,
      remoteMLKEMPublicKey: remoteMLKEMPublicKey,
    );
  }

  static Future<void> _skipMessageKeys(Sodium sodium, RatchetState state, int until) async {
    if (state.receivingChainKey == null) return;
    if (state.nReceiving + maxSkip < until) throw Exception('Too many messages skipped');
    while (state.nReceiving < until) {
      final res = await _kdfChain(sodium, state.receivingChainKey!);
      state.receivingChainKey!.dispose();
      state.receivingChainKey = res[0];
      final messageKey = res[1];
      state.skippedMessageKeys['${state.remoteDhPublicKey}_${state.nReceiving}'] = messageKey;
      state.nReceiving++;
    }
  }

  static Future<void> _dhRatchetStep(
    SodiumSumo sodium,
    RatchetState state,
    Uint8List remoteDhPublicKey,
    int pn,
    {Uint8List? remoteMLKEMCiphertext}
  ) async {
    await _skipMessageKeys(sodium, state, pn);
    state.pn = state.nSending;
    state.nSending = 0;
    state.nReceiving = 0;
    state.remoteDhPublicKey = remoteDhPublicKey;

    final dhSecret = sodium.crypto.scalarmult(
      n: state.dhKeyPair.secretKey,
      p: state.remoteDhPublicKey,
    );
    final classicalBytes = await dhSecret.extractBytes();
    dhSecret.dispose();

    Uint8List pqBytes = Uint8List(0);
    if (remoteMLKEMCiphertext != null && state.localMLKEMKeyPair != null) {
      try {
        final kem = KEM.create('ML-KEM-768')!;
        pqBytes = kem.decapsulate(remoteMLKEMCiphertext, Uint8List.fromList(state.localMLKEMKeyPair!.secretKey));
        kem.dispose();
      } catch (e) {
        throw Exception('PQC Decapsulation failed: $e');
      }
    }

    final combinedSecret = Uint8List(classicalBytes.length + pqBytes.length);
    combinedSecret.setRange(0, classicalBytes.length, classicalBytes);
    combinedSecret.setRange(classicalBytes.length, combinedSecret.length, pqBytes);

    final rootKdfResult = await _kdfRoot(sodium, state.rootKey, combinedSecret);
    state.rootKey.dispose();
    state.rootKey = rootKdfResult[0];
    state.receivingChainKey?.dispose();
    state.receivingChainKey = rootKdfResult[1];

    state.dhKeyPair.secretKey.dispose();
    state.dhKeyPair = sodium.crypto.box.keyPair();

    final newDhSecret = sodium.crypto.scalarmult(
      n: state.dhKeyPair.secretKey,
      p: state.remoteDhPublicKey,
    );
    final newClassicalBytes = await newDhSecret.extractBytes();
    newDhSecret.dispose();

    Uint8List newPQBytes = Uint8List(0);

    final newCombinedSecret = Uint8List(newClassicalBytes.length + newPQBytes.length);
    newCombinedSecret.setRange(0, newClassicalBytes.length, newClassicalBytes);

    final rootKdfResult2 = await _kdfRoot(sodium, state.rootKey, newCombinedSecret);
    state.rootKey.dispose();
    state.rootKey = rootKdfResult2[0];
    state.sendingChainKey?.dispose();
    state.sendingChainKey = rootKdfResult2[1];
  }

  static Future<List<SecureKey>> _kdfRoot(Sodium sodium, SecureKey rootKey, Uint8List ikm) async {
    final rootKeyBytes = await rootKey.extractBytes();
    final prk = HKDF.compute(ikm: ikm, salt: rootKeyBytes, info: Uint8List.fromList('DoubleRatchetRoot'.codeUnits), length: 64);
    final rk = await sodium.secureCopy(prk.sublist(0, 32));
    final ck = await sodium.secureCopy(prk.sublist(32, 64));
    return [rk, ck];
  }

  static Future<List<SecureKey>> _kdfChain(Sodium sodium, SecureKey chainKey) async {
    final chainKeyBytes = await chainKey.extractBytes();
    final mk = HKDF.compute(ikm: Uint8List.fromList([0x01]), salt: chainKeyBytes, info: Uint8List.fromList('DoubleRatchetMessage'.codeUnits), length: 32);
    final nextCk = HKDF.compute(ikm: Uint8List.fromList([0x02]), salt: chainKeyBytes, info: Uint8List.fromList('DoubleRatchetChain'.codeUnits), length: 32);
    return [await sodium.secureCopy(nextCk), await sodium.secureCopy(mk)];
  }

  static Future<Uint8List> encrypt(RatchetState state, Uint8List plaintext, Uint8List ad) async {
    final sodium = await MySodiumInit.instance as SodiumSumo;
    if (state.sendingChainKey == null) {
       final dhSecret = sodium.crypto.scalarmult(n: state.dhKeyPair.secretKey, p: state.remoteDhPublicKey);
       final dhBytes = await dhSecret.extractBytes();
       final res = await _kdfRoot(sodium, state.rootKey, dhBytes);
       state.rootKey.dispose();
       state.rootKey = res[0];
       state.sendingChainKey = res[1];
       dhSecret.dispose();
    }

    final res = await _kdfChain(sodium, state.sendingChainKey!);
    state.sendingChainKey!.dispose();
    state.sendingChainKey = res[0];
    final messageKey = res[1];

    final nonce = sodium.randombytes.buf(sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes);
    final ciphertext = sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
      message: plaintext,
      additionalData: _buildAd(ad, state.dhKeyPair.publicKey, state.nSending, state.pn),
      nonce: nonce,
      key: messageKey,
    );

    var header = _buildHeader(state.dhKeyPair.publicKey, state.nSending, state.pn, nonce);

    if (state.localMLDSAKeyPair != null) {
       try {
         final sig = Signature.create('ML-DSA-65')!;
         final signature = sig.sign(Uint8List.fromList([...header, ...ciphertext]), Uint8List.fromList(state.localMLDSAKeyPair!.secretKey));
         sig.dispose();
         header = Uint8List.fromList([...header, ...signature]);
       } catch (e) {
         print('Signature failed: $e');
       }
    }

    messageKey.dispose();
    state.nSending++;
    return Uint8List.fromList([...header, ...ciphertext]);
  }

  static Future<Uint8List> decrypt(RatchetState state, Uint8List ciphertextWithHeader, Uint8List ad) async {
    final sodium = await MySodiumInit.instance as SodiumSumo;
    final header = _parseHeader(ciphertextWithHeader, state.remoteMLDSAPublicKey != null);
    final ciphertext = ciphertextWithHeader.sublist(header.totalLength);

    if (state.remoteMLDSAPublicKey != null && header.signature != null) {
      final sig = Signature.create('ML-DSA-65')!;
      final actualSignedData = Uint8List.fromList([...ciphertextWithHeader.sublist(0, header.headerWithoutSigLength), ...ciphertext]);
      if (!sig.verify(actualSignedData, header.signature!, state.remoteMLDSAPublicKey!)) {
        sig.dispose();
        throw Exception('ML-DSA Signature verification failed');
      }
      sig.dispose();
    }

    final skippedKey = state.skippedMessageKeys['${header.remoteDhPublicKey}_${header.n}'];
    if (skippedKey != null) {
      final plaintext = sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
        cipherText: ciphertext,
        additionalData: _buildAd(ad, header.remoteDhPublicKey, header.n, header.pn),
        nonce: header.nonce,
        key: skippedKey,
      );
      state.skippedMessageKeys.remove('${header.remoteDhPublicKey}_${header.n}');
      skippedKey.dispose();
      return plaintext;
    }

    if (!_compareUint8Lists(state.remoteDhPublicKey, header.remoteDhPublicKey) || state.receivingChainKey == null) {
       await _dhRatchetStep(sodium, state, header.remoteDhPublicKey, header.pn);
    }

    await _skipMessageKeys(sodium, state, header.n);

    final res = await _kdfChain(sodium, state.receivingChainKey!);
    state.receivingChainKey!.dispose();
    state.receivingChainKey = res[0];
    final messageKey = res[1];

    final plaintext = sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
      cipherText: ciphertext,
      additionalData: _buildAd(ad, header.remoteDhPublicKey, header.n, header.pn),
      nonce: header.nonce,
      key: messageKey,
    );

    messageKey.dispose();
    state.nReceiving++;
    return plaintext;
  }

  static Uint8List _buildAd(Uint8List ad, Uint8List dhPk, int n, int pn) {
    final b = BytesBuilder();
    b.add(ad);
    b.add(dhPk);
    final data = ByteData(8);
    data.setUint32(0, n);
    data.setUint32(4, pn);
    b.add(data.buffer.asUint8List());
    return b.toBytes();
  }

  static Uint8List _buildHeader(Uint8List dhPk, int n, int pn, Uint8List nonce) {
    final b = BytesBuilder();
    b.add(dhPk);
    final data = ByteData(8);
    data.setUint32(0, n);
    data.setUint32(4, pn);
    b.add(data.buffer.asUint8List());
    b.add(nonce);
    return b.toBytes();
  }

  static _Header _parseHeader(Uint8List data, bool hasSignature) {
    final dhPk = data.sublist(0, 32);
    final bd = ByteData.view(data.buffer, data.offsetInBytes + 32, 8);
    final n = bd.getUint32(0);
    final pn = bd.getUint32(4);
    final nonce = data.sublist(40, 40 + 24);
    int offset = 40 + 24;
    Uint8List? signature;
    if (hasSignature) {
       signature = data.sublist(offset, offset + 3309);
       offset += 3309;
    }
    return _Header(dhPk, n, pn, nonce, offset, signature, 40 + 24);
  }

  static bool _compareUint8Lists(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class _Header {
  final Uint8List remoteDhPublicKey;
  final int n;
  final int pn;
  final Uint8List nonce;
  final int totalLength;
  final int headerWithoutSigLength;
  final Uint8List? signature;
  _Header(this.remoteDhPublicKey, this.n, this.pn, this.nonce, this.totalLength, this.signature, this.headerWithoutSigLength);
}
