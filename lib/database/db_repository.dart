import 'dart:typed_data';
import 'package:sqflite_sqlcipher/sqflite.dart';
import 'db_service.dart';

class MessageModel {
  final int? id;
  final String sender;
  final String recipient;
  final Uint8List content;
  final int timestamp;

  MessageModel({this.id, required this.sender, required this.recipient, required this.content, required this.timestamp});

  Map<String, dynamic> toMap() => {
    'sender': sender,
    'recipient': recipient,
    'content': content,
    'timestamp': timestamp,
  };
}

class DatabaseRepository {
  Future<void> insertMessage(MessageModel msg) async {
    final db = await DatabaseService.instance;
    await db.insert('messages', msg.toMap());
  }

  Future<List<MessageModel>> getMessages(String peerId) async {
    final db = await DatabaseService.instance;
    final List<Map<String, dynamic>> maps = await db.query(
      'messages',
      where: 'sender = ? OR recipient = ?',
      whereArgs: [peerId, peerId],
      orderBy: 'timestamp ASC',
    );

    return List.generate(maps.length, (i) {
      return MessageModel(
        id: maps[i]['id'],
        sender: maps[i]['sender'],
        recipient: maps[i]['recipient'],
        content: maps[i]['content'],
        timestamp: maps[i]['timestamp'],
      );
    });
  }

  Future<void> saveSession(String peerId, Uint8List state) async {
    final db = await DatabaseService.instance;
    await db.insert(
      'sessions',
      {'peer_id': peerId, 'state': state},
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<Uint8List?> getSession(String peerId) async {
    final db = await DatabaseService.instance;
    final List<Map<String, dynamic>> maps = await db.query(
      'sessions',
      where: 'peer_id = ?',
      whereArgs: [peerId],
    );
    if (maps.isEmpty) return null;
    return maps.first['state'] as Uint8List;
  }
}
