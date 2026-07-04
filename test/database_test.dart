import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_shield/database/db_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // Mock secure storage for unit tests
  const storageChannel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(storageChannel, (MethodCall methodCall) async {
    if (methodCall.method == 'read') {
      return 'mock-db-key-must-be-long-enough-for-sqlcipher-32bytes';
    }
    return null;
  });

  // Mock sqflite_sqlcipher channel for getDatabasesPath
  const dbChannel = MethodChannel('com.davidmartos96.sqflite_sqlcipher');
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(dbChannel, (MethodCall methodCall) async {
    if (methodCall.method == 'getDatabasesPath') {
      return '.';
    }
    return null;
  });

  // Initialize sqflite ffi for desktop/test environment
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;

  group('Database Tests', () {
    test('Insert and Retrieve Message', () async {
      final repo = DatabaseRepository();
      final msg = MessageModel(
        sender: 'alice',
        recipient: 'bob',
        content: Uint8List.fromList('secret'.codeUnits),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );

      await repo.insertMessage(msg);
      final messages = await repo.getMessages('bob');

      expect(messages.isNotEmpty, true);
      expect(String.fromCharCodes(messages.first.content), equals('secret'));
    });

    test('Save and Load Session', () async {
      final repo = DatabaseRepository();
      final state = Uint8List.fromList([1, 2, 3, 4]);

      await repo.saveSession('bob', state);
      final loaded = await repo.getSession('bob');

      expect(loaded, equals(state));
    });
  });
}
