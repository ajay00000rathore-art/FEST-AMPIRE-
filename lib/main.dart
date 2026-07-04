import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'crypto/sodium_init.dart';
import 'crypto/double_ratchet.dart';
import 'crypto/pqc.dart';

void main() {
  runApp(const QuantumShieldApp());
}

class QuantumShieldApp extends StatelessWidget {
  const QuantumShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'QuantumShield Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blueGrey, brightness: Brightness.dark),
        useMaterial3: true,
      ),
      home: const CryptoDemoScreen(),
    );
  }
}

class CryptoDemoScreen extends StatefulWidget {
  const CryptoDemoScreen({super.key});

  @override
  State<CryptoDemoScreen> createState() => _CryptoDemoScreenState();
}

class _CryptoDemoScreenState extends State<CryptoDemoScreen> {
  String _status = 'Idle';
  String _output = 'Press the button to run a PQ-Double Ratchet handshake demo.';
  bool _isRunning = false;

  Future<void> _runDemo() async {
    setState(() {
      _isRunning = true;
      _status = 'Initializing...';
      _output = '';
    });

    try {
      final sodium = await MySodiumInit.instance;
      setState(() => _status = 'Generating Keys...');

      final aliceDh = sodium.crypto.box.keyPair();
      final bobDh = sodium.crypto.box.keyPair();
      final sharedRootKey = sodium.randombytes.buf(32);

      setState(() => _status = 'Initializing Ratchet...');
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

      setState(() => _status = 'Encrypting...');
      final message = Uint8List.fromList('Post-Quantum Secure Hello!'.codeUnits);
      final encrypted = await DoubleRatchetService.encrypt(aliceState, message, Uint8List(0));

      setState(() => _status = 'Decrypting...');
      final decrypted = await DoubleRatchetService.decrypt(bobState, encrypted, Uint8List(0));

      setState(() {
        _status = 'Success!';
        _output = 'Handshake Complete.\n\n'
            'Message: "Post-Quantum Secure Hello!"\n'
            'Ciphertext Length: ${encrypted.length} bytes\n'
            'Decrypted: "${String.fromCharCodes(decrypted)}"\n\n'
            'Double Ratchet state successfully synchronized between Alice and Bob.';
      });
    } catch (e) {
      setState(() {
        _status = 'Error';
        _output = 'Failed to run crypto demo: $e\n\n'
            'Note: This demo requires native libsodium and liboqs binaries to be correctly installed on the host system.';
      });
    } finally {
      setState(() => _isRunning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('QuantumShield Messenger Demo'),
        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    Text('Status: $_status', style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 8),
                    if (_isRunning) const LinearProgressIndicator(),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: SingleChildScrollView(
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.black26,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    _output,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _isRunning ? null : _runDemo,
              icon: const Icon(Icons.security),
              label: const Text('Run PQ-Ratchet Handshake'),
              style: ElevatedButton.styleFrom(padding: const EdgeInsets.all(16)),
            ),
          ],
        ),
      ),
    );
  }
}
