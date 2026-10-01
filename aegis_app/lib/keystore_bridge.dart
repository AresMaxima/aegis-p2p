import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

typedef AegisSetHardwareSecretC = Int32 Function(Pointer<Uint8> secretPtr, IntPtr secretLen);
typedef AegisSetHardwareSecretDart = int Function(Pointer<Uint8> secretPtr, int secretLen);

// F6-C — Typedefs vault persistence
typedef _VaultSetDirC = Int32 Function(Pointer<Utf8> pathPtr);
typedef _VaultSetDirDart = int Function(Pointer<Utf8> pathPtr);

typedef _VaultIsInitC = Int32 Function();
typedef _VaultIsInitDart = int Function();

typedef _VaultInitC = Int32 Function(Pointer<Utf8> pinPtr);
typedef _VaultInitDart = int Function(Pointer<Utf8> pinPtr);

typedef _VaultUnlockC = Int32 Function(Pointer<Utf8> pinPtr);
typedef _VaultUnlockDart = int Function(Pointer<Utf8> pinPtr);

typedef _VaultWipeC = Int32 Function();
typedef _VaultWipeDart = int Function();

/// Résultat d'un appel `vaultUnlock`.
///
/// Mappé sur les codes retour de `aegis_vault_unlock` (C ABI) :
///   0  → real
///   1  → decoy
///   2  → needsInitialization
///  -1  → error (interne, IO, ROOT_KEY absente)
enum VaultUnlockStatus { real, decoy, needsInitialization, error }

/// Pont Dart ↔ Kotlin (MethodChannel) ↔ Rust (JNI + FFI).
///
/// Deux flux :
///   1. initializeHardwareSecurity() : charge la ROOT_KEY depuis le StrongBox
///      via Kotlin, puis la transmet à Rust via FFI (aegis_set_hardware_secret).
///   2. deriveMasterKey(pin) : envoie le vault PIN à Kotlin, qui appelle le
///      JNI aegis_derive_and_set_master_key. Rust combine ROOT_KEY || PIN
///      via HKDF-SHA256 → MASTER_KEY.
///
/// F6-C (2026-09-30) — Vault persistance 100% Rust :
///   3. vaultSetDir(path)  : configure le dossier où vit `vault.json`.
///   4. vaultIsInitialized() : vrai si un vault chiffré existe (HMAC verifier).
///   5. vaultInit(pin)     : crée le vault (salt aléatoire + verifier HMAC).
///   6. vaultUnlock(pin)   : vérifie le verifier en constant-time.
///   7. vaultWipe()        : efface vault.json + ROOT_KEY + MASTER_KEY.
///
/// Plus aucune donnée vault ne transite par SharedPreferences.
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

  // ==========================================================================
  // F6-C — VAULT PERSISTANCE (100% Rust)
  // ==========================================================================

  /// Configure le répertoire de persistance du vault (`vault.json`).
  ///
  /// Doit être appelé UNE FOIS au démarrage de l'app, AVANT toute autre
  /// opération vault (`vaultIsInitialized`, `vaultInit`, `vaultUnlock`).
  ///
  /// Côté Dart : passer `(await getApplicationDocumentsDirectory()).path`.
  ///
  /// Retourne `true` si le dossier est valide et a été enregistré.
  static bool vaultSetDir(String dirPath) {
    try {
      final nativeFn = _lib
          .lookupFunction<_VaultSetDirC, _VaultSetDirDart>(
            'aegis_vault_set_dir',
          );

      final ptr = dirPath.toNativeUtf8();
      final result = nativeFn(ptr);
      malloc.free(ptr);

      return result == 0;
    } catch (e) {
      return false;
    }
  }

  /// Vrai si un `vault.json` valide existe dans le répertoire configuré.
  ///
  /// Si `vaultSetDir` n'a pas été appelé, retourne `false` (par sécurité).
  static bool vaultIsInitialized() {
    try {
      final nativeFn = _lib
          .lookupFunction<_VaultIsInitC, _VaultIsInitDart>(
            'aegis_vault_is_initialized',
          );
      return nativeFn() == 1;
    } catch (e) {
      return false;
    }
  }

  /// Initialise un nouveau vault avec le PIN fourni.
  ///
  /// Prérequis :
  ///   • `vaultSetDir` doit avoir été appelé.
  ///   • `initializeHardwareSecurity` doit avoir réussi (ROOT_KEY en mémoire).
  ///
  /// Effet : écrit `vault.json` (salt aléatoire + verifier HMAC-SHA256).
  /// Écrase tout vault existant.
  ///
  /// Retourne `true` si l'init a réussi.
  static bool vaultInit(String pin) {
    if (pin.isEmpty) return false;
    try {
      final nativeFn = _lib
          .lookupFunction<_VaultInitC, _VaultInitDart>(
            'aegis_vault_init',
          );

      final ptr = pin.toNativeUtf8();
      final result = nativeFn(ptr);
      malloc.free(ptr);

      return result == 0;
    } catch (e) {
      return false;
    }
  }

  /// Tente de déverrouiller le vault avec le PIN fourni.
  ///
  /// Retourne :
  ///   • `VaultUnlockStatus.real`               : PIN correct
  ///   • `VaultUnlockStatus.decoy`              : PIN incorrect
  ///   • `VaultUnlockStatus.needsInitialization`: aucun vault.json
  ///   • `VaultUnlockStatus.error`              : erreur interne
  static VaultUnlockStatus vaultUnlock(String pin) {
    if (pin.isEmpty) return VaultUnlockStatus.error;
    try {
      final nativeFn = _lib
          .lookupFunction<_VaultUnlockC, _VaultUnlockDart>(
            'aegis_vault_unlock',
          );

      final ptr = pin.toNativeUtf8();
      final result = nativeFn(ptr);
      malloc.free(ptr);

      switch (result) {
        case 0:
          return VaultUnlockStatus.real;
        case 1:
          return VaultUnlockStatus.decoy;
        case 2:
          return VaultUnlockStatus.needsInitialization;
        default:
          return VaultUnlockStatus.error;
      }
    } catch (e) {
      return VaultUnlockStatus.error;
    }
  }

  /// Efface `vault.json` + ROOT_KEY + MASTER_KEY.
  ///
  /// Retourne `true` si le wipe a réussi.
  static bool vaultWipe() {
    try {
      final nativeFn = _lib
          .lookupFunction<_VaultWipeC, _VaultWipeDart>(
            'aegis_vault_wipe',
          );
      return nativeFn() == 0;
    } catch (e) {
      return false;
    }
  }
}