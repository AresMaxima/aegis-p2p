import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/crypto_service.dart';

// =========================================================================
// VALIDATION DE MOT DE PASSE FORT / PHRASE CLÉ
// =========================================================================

enum PasswordStrength { weak, medium, strong, veryStrong }

class PasswordValidator {
  static const int minLength = 12;
  static const int passphraseMinWords = 4;

  /// Évalue la force d'un mot de passe.
  static PasswordStrength evaluate(String password) {
    if (password.isEmpty) return PasswordStrength.weak;
    if (password.length < 8) return PasswordStrength.weak;

    // Rejette les motifs très courants (même en sous-chaîne).
    final lower = password.toLowerCase();
    const bannedPatterns = [
      '123456', 'password', 'azerty', 'qwerty', 'admin',
      'aegis', 'letmein', 'welcome', 'monkey', 'dragon',
      'master', 'iloveyou', 'superman', 'football',
    ];
    for (final p in bannedPatterns) {
      if (lower.contains(p)) return PasswordStrength.weak;
    }

    // Rejette les répétitions excessives (aaaa, 1111, etc.).
    if (RegExp(r'(.)\1{3,}').hasMatch(password)) {
      return PasswordStrength.weak;
    }

    // Détection phrase clé : 4+ mots séparés par espace, chaque mot >= 3 car.
    final words = password.trim().split(RegExp(r'\s+'));
    final isPassphrase = words.length >= passphraseMinWords &&
        words.every((w) => w.length >= 3);

    // Compte les classes de caractères.
    int classes = 0;
    if (RegExp(r'[a-z]').hasMatch(password)) classes++;
    if (RegExp(r'[A-Z]').hasMatch(password)) classes++;
    if (RegExp(r'[0-9]').hasMatch(password)) classes++;
    if (RegExp(r'[^a-zA-Z0-9]').hasMatch(password)) classes++;

    if (password.length < minLength) {
      return classes >= 3 ? PasswordStrength.medium : PasswordStrength.weak;
    }

    if (isPassphrase) return PasswordStrength.veryStrong;
    if (classes >= 3 && password.length >= 16) return PasswordStrength.veryStrong;
    if (classes >= 3) return PasswordStrength.strong;
    if (classes == 2 && password.length >= 16) return PasswordStrength.strong;
    return PasswordStrength.medium;
  }

  /// Retourne null si valide, sinon un message d'erreur.
  static String? validate(String password) {
    if (password.isEmpty) return "Mot de passe requis.";
    if (password.length < minLength) {
      return "Minimum $minLength caractères requis. Astuce : utilisez une "
             "phrase clé de $passphraseMinWords mots ou plus.";
    }

    final strength = evaluate(password);
    if (strength == PasswordStrength.weak) {
      return "Mot de passe trop faible. Évitez les suites simples, "
             "utilisez 3 classes de caractères ou une phrase de "
             "$passphraseMinWords mots.";
    }
    return null;
  }

  /// Vrai ssi le mot de passe est acceptable (medium ou mieux).
  static bool isAcceptable(String password) {
    return validate(password) == null;
  }

  /// Couleur associée à la force (retournée comme int ARGB pour éviter
  /// la dépendance Flutter dans ce fichier).
  static int strengthColor(PasswordStrength s) {
    switch (s) {
      case PasswordStrength.weak:       return 0xFFE53935; // rouge
      case PasswordStrength.medium:     return 0xFFFF9800; // orange
      case PasswordStrength.strong:     return 0xFF8BC34A; // vert clair
      case PasswordStrength.veryStrong: return 0xFF4CAF50; // vert foncé
    }
  }

  static String strengthLabel(PasswordStrength s) {
    switch (s) {
      case PasswordStrength.weak:       return "FAIBLE";
      case PasswordStrength.medium:     return "MOYEN";
      case PasswordStrength.strong:     return "FORT";
      case PasswordStrength.veryStrong: return "EXCELLENT";
    }
  }
}

// =========================================================================
// TYPES DE SESSION
// =========================================================================

enum VaultSessionType { real, decoy, needsInitialization }

class SessionResult {
  final VaultSessionType type;
  final String payload;

  SessionResult({required this.type, required this.payload});
}

// =========================================================================
// VAULT DE SESSION
// =========================================================================

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
    // Validation stricte : minimum 12 caractères, force >= medium.
    if (!PasswordValidator.isAcceptable(chosenPin)) return false;
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