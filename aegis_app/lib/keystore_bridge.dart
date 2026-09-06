import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

typedef AegisSetHardwareSecretC = Int32 Function(Pointer<Uint8> secretPtr, IntPtr secretLen);
typedef AegisSetHardwareSecretDart = int Function(Pointer<Uint8> secretPtr, int secretLen);

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
}