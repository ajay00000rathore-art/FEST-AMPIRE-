import 'dart:ffi';
import 'dart:io';
import 'package:sodium/sodium_sumo.dart';

class MySodiumInit {
  static SodiumSumo? _sodium;

  static Future<SodiumSumo> get instance async {
    if (_sodium != null) return _sodium!;
    _sodium = await MySodiumInit.init();
    return _sodium!;
  }

  static Future<SodiumSumo> init() async {
    return await SodiumSumoInit.init(() {
      if (Platform.isLinux) {
        final paths = [
          'libsodium.so',
          'libsodium.so.23',
          '/usr/lib/x86_64-linux-gnu/libsodium.so.23',
          '/usr/local/lib/libsodium.so',
        ];
        for (var path in paths) {
          try {
            return DynamicLibrary.open(path);
          } catch (_) {}
        }
      }
      return DynamicLibrary.open('libsodium.so');
    });
  }
}
