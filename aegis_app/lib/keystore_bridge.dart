import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

typedef AegisSetHardwareSecretC = Int32 Function(Pointer<Uint8> secretPtr, IntPtr secretLen);
typedef AegisSetHardwareSecretDart = int Function(Pointer<Uint8> secretPtr, int secretLen);

/// Pont Dart ↔ Kotlin (MethodChannel) ↔ Rust (JNI + FFI).
///
/// Deux flux :
///   1. initializeHardwareSecurity() : charge la ROOT_KEY depuis le StrongBox
///      via Kotlin, puis la transmet à Rust via FFI (aegis_set_hardware_secret).
///   2. deriveMasterKey(pin) : envoie le vault PIN à Kotlin, qui appelle le
///      JNI aegis_derive_and_set_master_key. Rust combine ROOT_KEY || PIN
///      via HKDF-SHA256 → MASTER_KEY.
///
/// Option 2 (audit 2026-09-20) : pas de biométrie. Deux facteurs :
///   • Matériel  : StrongBox (scellée dans la puce).
///   • Connaissance : vault PIN.
class KeystoreBridge {
  static const MethodChannel _channel = MethodChannel('com.aegis/keystore');
  static DynamicLibrary? _nativeLib;

  static DynamicLibrary get _lib {
    if (_nativeLib != null) return _nativeLib!;
    if (Platform.isAndroid) {
      _nativeLib = DynamicLibrary.open('libaegis_core.so');
    } else {
      throw UnsupportedError('Plateforme non supportée');
    }
    return _nativeLib!;
  }

  /// Étape 1 : charge la ROOT_KEY StrongBox/TEE et la transmet à Rust.
  ///
  /// Kotlin → HardwareKeystore.getHardwareSecret() → byte[32]
  /// Dart   → FFI aegis_set_hardware_secret(ptr, 32)
  /// Rust   → ROOT_KEY (mémoire)
  ///
  /// Retourne `true` si ROOT_KEY est bien initialisée côté Rust.
  static Future<bool> initializeHardwareSecurity({bool isVaultEmpty = false}) async {
    try {
      final Uint8List? secretBytes = await _channel.invokeMethod<Uint8List>(
        'getHardwareSecret',
        {'isVaultEmpty': isVaultEmpty},
      );

      if (secretBytes == null || secretBytes.length != 32) {
        return false;
      }

      final Pointer<Uint8> ptr = calloc<Uint8>(secretBytes.length);
      final blob = ptr.asTypedList(secretBytes.length);
      blob.setAll(0, secretBytes);

      final nativeSetSecret = _lib
          .lookupFunction<AegisSetHardwareSecretC, AegisSetHardwareSecretDart>(
            'aegis_set_hardware_secret',
          );

      final int result = nativeSetSecret(ptr, secretBytes.length);
      calloc.free(ptr);

      return result == 0;
    } on PlatformException {
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Étape 2 : dérive la master_key à partir du vault PIN.
  ///
  /// Dart   → MethodChannel.deriveMasterKey(pin)
  /// Kotlin → JNI aegis_derive_and_set_master_key(pin)
  /// Rust   → HKDF-SHA256(ROOT_KEY || PIN, salt, info) → MASTER_KEY
  ///
  /// Retourne `true` si la master_key a été dérivée avec succès.
  ///
  /// Prérequis : `initializeHardwareSecurity()` doit avoir réussi avant.
  static Future<bool> deriveMasterKey(String pin) async {
    if (pin.isEmpty) {
      return false;
    }

    try {
      final bool? ok = await _channel.invokeMethod<bool>(
        'deriveMasterKey',
        {'pin': pin},
      );
      return ok == true;
    } on PlatformException {
      return false;
    } catch (e) {
      return false;
    }
  }
}