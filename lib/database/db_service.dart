import 'dart:typed_data';
import 'package:sqflite_sqlcipher/sqflite.dart';
import 'package:path/path.dart';
import '../storage/hardware_key_storage.dart';
import '../crypto/sodium_init.dart';

class DatabaseService {
  static Database? _db;
  static const String _dbName = 'quantum_shield.db';
  static const String _dbKeyAlias = 'database_encryption_key';

  static Future<Database> get instance async {
    if (_db != null) return _db!;
    _db = await _initDb();
    return _db!;
  }

  static Future<Database> _initDb() async {
    final storage = HardwareKeyStorage();
    String? dbKey = await storage.getKeyHandle(_dbKeyAlias);

    if (dbKey == null) {
      final sodium = await MySodiumInit.instance;
      final secureKey = sodium.randombytes.buf(32);
      await storage.storePrivateKey(_dbKeyAlias, secureKey);
      dbKey = await storage.getKeyHandle(_dbKeyAlias);
    }

    final dbPath = await getDatabasesPath();
    final path = join(dbPath, _dbName);

    return await openDatabase(
      path,
      password: dbKey,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            recipient TEXT,
            content BLOB,
            timestamp INTEGER
          )
        ''');
        await db.execute('''
          CREATE TABLE sessions (
            peer_id TEXT PRIMARY KEY,
            state BLOB
          )
        ''');
        await db.execute('''
          CREATE TABLE contacts (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            pre_key_bundle BLOB
          )
        ''');
      },
    );
  }
}
