import 'dart:async';
import '../keystore_bridge.dart';

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
// VAULT DE SESSION — F6-C (100% Rust)
// =========================================================================
//
// La persistance est intégralement déléguée à Rust :
//   • vault.json (filesDir) contient { version, salt, verifier }.
//   • Aucun PIN n'est jamais persisté.
//   • Le verifier = HMAC-SHA256(MASTER_KEY, salt || TAG).
//   • MASTER_KEY = HKDF-SHA256(ROOT_KEY || PIN) — ROOT_KEY vit
//     exclusivement dans le StrongBox.
//
// Plus de SharedPreferences, plus de hash PIN côté Dart.
// Le sel statique `_appSalt` et `CryptoService.deriveKey` ont été retirés
// (l'ancien hash PIN Dart est remplacé par le verifier HMAC en Rust).
//
// IMPORTANT — Ordre d'initialisation (géré par main.dart) :
//   1. KeystoreBridge.vaultSetDir(docsDir)
//   2. KeystoreBridge.initializeHardwareSecurity()
//   3. (PIN saisi par l'utilisateur) → initializeMasterPin / unlockSession
//
// L'API publique reste identique pour main.dart :
//   • isVaultInitialized() -> Future<bool>
//   • initializeMasterPin(pin) -> Future<bool>
//   • unlockSession(pin) -> Future<SessionResult>

class SessionVault {
  /// Délai minimum de réponse pour l'unlock (protection timing).
  static const int _unlockMinLatencyMs = 1500;

  /// Vrai si un vault chiffré existe déjà.
  Future<bool> isVaultInitialized() async {
    return KeystoreBridge.vaultIsInitialized();
  }

  /// Initialise le vault avec le PIN choisi.
  ///
  /// Vérifications préalables :
  ///   • Force du PIN (PasswordValidator).
  ///   • FFI `aegis_vault_init` → true si OK.
  ///
  /// Prérequis : `KeystoreBridge.vaultSetDir()` + `initializeHardwareSecurity()`
  /// doivent avoir réussi AVANT l'appel.
  Future<bool> initializeMasterPin(String chosenPin) async {
    if (!PasswordValidator.isAcceptable(chosenPin)) return false;
    return KeystoreBridge.vaultInit(chosenPin);
  }

  /// Tente de déverrouiller le vault avec le PIN fourni.
  ///
  /// Retourne :
  ///   • `real`               → PIN correct
  ///   • `decoy`              → PIN incorrect (ou erreur interne)
  ///   • `needsInitialization`→ aucun vault
  Future<SessionResult> unlockSession(String userPin) async {
    final Stopwatch stopwatch = Stopwatch()..start();

    final status = KeystoreBridge.vaultUnlock(userPin);

    // Latence minimum : évite de révéler par timing si le verifier
    // est proche du match (le HMAC-SHA256 Rust est déjà constant-time,
    // ceci est une marge défensive).
    stopwatch.stop();
    final int elapsedMs = stopwatch.elapsedMilliseconds;
    if (elapsedMs < _unlockMinLatencyMs) {
      await Future.delayed(
        Duration(milliseconds: _unlockMinLatencyMs - elapsedMs),
      );
    }

    switch (status) {
      case VaultUnlockStatus.real:
        return SessionResult(
          type: VaultSessionType.real,
          payload: "AEGIS_REAL_CORE_ACTIVE_PAYLOAD",
        );
      case VaultUnlockStatus.decoy:
        return SessionResult(
          type: VaultSessionType.decoy,
          payload: "DECOY_GENERATED_SESSION",
        );
      case VaultUnlockStatus.needsInitialization:
        return SessionResult(
          type: VaultSessionType.needsInitialization,
          payload: "VAULT_NOT_INITIALIZED",
        );
      case VaultUnlockStatus.error:
        // En cas d'erreur interne : traiter comme decoy (pas de fuite).
        return SessionResult(
          type: VaultSessionType.decoy,
          payload: "ERROR_FALLBACK",
        );
    }
  }

  /// Efface totalement le vault (fichier + clés RAM).
  ///
  /// Usage : réinitialisation volontaire par l'utilisateur.
  Future<bool> wipeVault() async {
    return KeystoreBridge.vaultWipe();
  }
}