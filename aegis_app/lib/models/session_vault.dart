import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/crypto_service.dart';

enum VaultSessionType { real, decoy, needsInitialization }

class SessionResult {
  final VaultSessionType type;
  final String payload;

  SessionResult({required this.type, required this.payload});
}

class SessionVault {
  final CryptoService _cryptoService = CryptoService();

  static final Uint8List _appSalt = Uint8List.fromList([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
  ]);

  Future<bool> isVaultInitialized() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.containsKey('aegis_master_hash');
  }

  Future<bool> initializeMasterPin(String chosenPin) async {
    if (chosenPin.length < 4) return false;
    final prefs = await SharedPreferences.getInstance();

    final SecretKey key = await _cryptoService.deriveKey(chosenPin, _appSalt);
    final bytes = await key.extractBytes();
    final hashHex = base64Encode(bytes);

    return await prefs.setString('aegis_master_hash', hashHex);
  }

  Future<SessionResult> unlockSession(String userPin) async {
    final Stopwatch stopwatch = Stopwatch()..start();
    final prefs = await SharedPreferences.getInstance();

    if (!prefs.containsKey('aegis_master_hash')) {
      return SessionResult(
        type: VaultSessionType.needsInitialization,
        payload: "VAULT_NOT_INITIALIZED",
      );
    }

    final savedHashHex = prefs.getString('aegis_master_hash');
    final SecretKey derivedKey = await _cryptoService.deriveKey(userPin, _appSalt);
    final derivedBytes = await derivedKey.extractBytes();
    final currentHashHex = base64Encode(derivedBytes);

    bool isValid = (savedHashHex == currentHashHex);

    stopwatch.stop();
    final int elapsedMs = stopwatch.elapsedMilliseconds;
    const int targetMs = 1500;
    if (elapsedMs < targetMs) {
      await Future.delayed(Duration(milliseconds: targetMs - elapsedMs));
    }

    if (isValid) {
      return SessionResult(
        type: VaultSessionType.real,
        payload: "AEGIS_REAL_CORE_ACTIVE_PAYLOAD",
      );
    } else {
      return SessionResult(
        type: VaultSessionType.decoy,
        payload: "DECOY_GENERATED_SESSION",
      );
    }
  }
}