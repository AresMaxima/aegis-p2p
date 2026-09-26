import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// 1. Implémentation stricte du wrapper Result<T, E> (M6)
class Result<T, E> {
  final T? value;
  final E? error;
  final bool isOk;

  Result.ok(this.value) : error = null, isOk = true;
  Result.err(this.error) : value = null, isOk = false;
}

// 2. Définition des signatures FFI natives
typedef InitVaultPathNative = Int32 Function(Pointer<Utf8> path);
typedef InitVaultPathDart = int Function(Pointer<Utf8> path);

typedef PanicPurgeNative = Void Function();
typedef PanicPurgeDart = void Function();

class AegisNativeBindings {
  static late final DynamicLibrary _lib;
  static late final InitVaultPathDart _initVaultPath;
  static late final PanicPurgeDart _panicPurge;
  
  static bool _initialized = false;

  static void _init() {
    if (_initialized) return;
    if (Platform.isAndroid) {
      _lib = DynamicLibrary.open('libaegis_core.so');
    } else {
      throw UnsupportedError('Plateforme non sécurisée/supportée');
    }

    _initVaultPath = _lib.lookupFunction<InitVaultPathNative, InitVaultPathDart>('aegis_init_vault_path');
    _panicPurge = _lib.lookupFunction<PanicPurgeNative, PanicPurgeDart>('aegis_panic_purge');
    _initialized = true;
  }

  // 3. Encapsulation des appels dans Result<T, E>
  static Result<int, String> initVaultPath(String path) {
    _init();
    final ptr = path.toNativeUtf8();
    try {
      final code = _initVaultPath(ptr);
      if (code == 0) {
        return Result.ok(code);
      } else {
        return Result.err('Native Error: $code');
      }
    } catch (e) {
      return Result.err(e.toString());
    } finally {
      calloc.free(ptr);
    }
  }

  static Result<void, String> panicPurge() {
    _init();
    try {
      _panicPurge();
      return Result.ok(null);
    } catch (e) {
      return Result.err(e.toString());
    }
  }
}