// aegis_app/lib/updater_bridge.dart
//
// P0-A.8c.1 (2026-10-19) — Pont Dart ↔ Kotlin ↔ Rust pour l'updater in-app (P-6).
// C82 (2026-10-22) — Fetch manifest via Tor (HTTP-over-Tor).
//
// Chaîne de confiance Q22-Q27 :
//   Q22 — Dart appelle FFI Rust aegis_tor_fetch_http() qui fetch le manifest
//         + sa signature via Tor (HTTP-over-Tor, .onion aresmaxima.com).
//         Puis appelle FFI Rust aegis_verify_update_signature() pour valider
//         ed25519. Si OK, parse le JSON.
//   Q23 — Kotlin télécharge l'APK (OkHttp, whitelist aresmaxima.com).
//   Q24 — Kotlin vérifie SHA-256 en temps constant.
//   Q25 — Kotlin lance l'installateur via FileProvider.
//   Q26 — Kotlin vérifie canRequestPackageInstalls() avant.
//   Q27 — Kotlin supprime l'APK post-install.
//
// C82 (strict) : si Tor n'est pas disponible (StrongBox absent, réseau
// bloqué, .onion introuvable), l'update est DIFFÉRÉ. Pas de fallback HTTPS
// (qui exposerait l'IP au serveur). L'utilisateur voit "Tor requis pour
// vérifier les mises à jour".

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

// =========================================================================
// FFI typedefs
// =========================================================================

typedef _VerifyUpdateSigC = Int32 Function(
  Pointer<Uint8> manifestPtr,
  IntPtr manifestLen,
  Pointer<Uint8> sigPtr,
  Pointer<Uint8> pubkeyPtr,
);
typedef _VerifyUpdateSigDart = int Function(
  Pointer<Uint8> manifestPtr,
  int manifestLen,
  Pointer<Uint8> sigPtr,
  Pointer<Uint8> pubkeyPtr,
);

typedef _TorFetchHttpC = Int32 Function(
  Pointer<Uint8> outManifestPtr,
  Pointer<IntPtr> outManifestLen,
  Pointer<Uint8> outSigPtr,
  Pointer<IntPtr> outSigLen,
);
typedef _TorFetchHttpDart = int Function(
  Pointer<Uint8> outManifestPtr,
  Pointer<IntPtr> outManifestLen,
  Pointer<Uint8> outSigPtr,
  Pointer<IntPtr> outSigLen,
);

// =========================================================================
// Constantes cryptographiques et réseau
// =========================================================================

/// Clé publique ed25519 admin (32 octets).
/// Doit matcher exactement `ADMIN_PUBLIC_KEY_BYTES` dans aegis-core/src/lib.rs.
const List<int> _adminPublicKeyBytes = <int>[
  0xbb, 0x45, 0xa7, 0xdb, 0x9a, 0x81, 0xc9, 0x60,
  0x9d, 0xbc, 0x8f, 0x93, 0xab, 0x87, 0x9c, 0x2f,
  0x38, 0x2f, 0xc7, 0x3c, 0xb3, 0x87, 0x1c, 0xb1,
  0x03, 0xa4, 0xb6, 0x53, 0xc3, 0x85, 0xcd, 0x87,
];

/// Bornes de sécurité anti-DoS (miroir de lib.rs).
const int _maxManifestBytes = 64 * 1024;
const int _sigLength = 64;

// =========================================================================
// Modèles
// =========================================================================

/// Codes retour de l'updater. Symétriques avec AegisUpdater.kt (Kotlin)
/// et updater::UpdateError (Rust).
class UpdateRc {
  static const int ok = 0;
  static const int networkError = -1;
  static const int hashMismatch = -2;
  static const int permissionDenied = -3;
  static const int ioError = -4;
  static const int invalidUrl = -5;
  static const int alreadyRunning = -6;
  static const int sizeExceeded = -8;

  // Codes de la FFI Rust (updater::UpdateError::to_code)
  static const int invalidSignature = -60;
  static const int parseError = -62;

  // Codes spécifiques C82 (fetch via Tor)
  static const int torUnavailable = -70;
  static const int torFetchFailed = -71;

  static String describe(int rc) {
    switch (rc) {
      case ok: return 'OK';
      case networkError: return 'Erreur réseau';
      case hashMismatch: return 'Hash SHA-256 non conforme';
      case permissionDenied: return 'Installation non autorisée (Paramètres)';
      case ioError: return 'Erreur d\'écriture';
      case invalidUrl: return 'URL invalide (whitelist aresmaxima.com)';
      case alreadyRunning: return 'Mise à jour déjà en cours';
      case sizeExceeded: return 'APK trop volumineux';
      case invalidSignature: return 'Signature ed25519 invalide';
      case parseError: return 'JSON manifeste invalide';
      case torUnavailable: return 'Tor indisponible — vérifiez StrongBox';
      case torFetchFailed: return 'Fetch Tor échoué — vérifiez votre connexion';
      default: return 'Erreur inconnue ($rc)';
    }
  }
}

/// Manifeste de mise à jour (désérialisé depuis le JSON signé).
///
/// Tous les champs sont **signés** : le manifeste entier est couvert
/// par la signature ed25519 vérifiée par Rust avant tout parsing Dart.
class UpdateManifest {
  final String version;
  final String apkUrl;
  final String sha256Hex;
  final bool forceUpdate;

  const UpdateManifest({
    required this.version,
    required this.apkUrl,
    required this.sha256Hex,
    required this.forceUpdate,
  });

  @override
  String toString() =>
      'UpdateManifest(version=$version, forceUpdate=$forceUpdate, '
      'sha256=${sha256Hex.substring(0, 8)}…)';
}

/// Résultat d'un `checkForUpdates`. Trois états mutuellement exclusifs :
///   • `errorRc != 0` → échec (voir UpdateRc.describe)
///   • `manifest != null` → mise à jour disponible
///   • ni l'un ni l'autre → à jour
class UpdateCheckResult {
  final UpdateManifest? manifest;
  final int errorRc;

  const UpdateCheckResult._({this.manifest, this.errorRc = 0});

  factory UpdateCheckResult.upToDate() => const UpdateCheckResult._();
  factory UpdateCheckResult.available(UpdateManifest m) =>
      UpdateCheckResult._(manifest: m);
  factory UpdateCheckResult.failure(int rc) => UpdateCheckResult._(errorRc: rc);

  bool get hasUpdate => manifest != null && errorRc == 0;
  bool get hasError => errorRc != 0;
}

/// Événement de progression pendant le téléchargement APK.
class UpdateProgress {
  final int downloaded;
  final int total;

  const UpdateProgress(this.downloaded, this.total);

  double get fraction =>
      total > 0 ? (downloaded / total).clamp(0.0, 1.0).toDouble() : 0.0;
}

// =========================================================================
// UpdaterBridge
// =========================================================================

/// Pont Dart ↔ Kotlin (MethodChannel `com.aegis/updater`) ↔ Rust (FFI).
///
/// Cycle de vie typique (P0-A.8c.2 / P0-A.8c.3) :
///   1. `await UpdaterBridge.canInstall()` → vérifie REQUEST_INSTALL_PACKAGES
///   2. Si false → `await UpdaterBridge.openInstallSettings()` puis retour
///   3. `await UpdaterBridge.checkForUpdates(currentVersion: '3.1.0')`
///      → si `.hasUpdate`, afficher la bannière / le dialogue
///   4. Écouter `UpdaterBridge.progressStream` pour la barre de progression
///   5. `await UpdaterBridge.downloadAndInstall(manifest)` → lance l'Intent
class UpdaterBridge {
  static const MethodChannel _channel = MethodChannel('com.aegis/updater');
  static DynamicLibrary? _nativeLib;

  static final StreamController<UpdateProgress> _progressController =
      StreamController<UpdateProgress>.broadcast();
  static bool _reverseHandlerSet = false;

  static DynamicLibrary get _lib {
    if (_nativeLib != null) return _nativeLib!;
    if (Platform.isAndroid) {
      _nativeLib = DynamicLibrary.open('libaegis_core.so');
    } else {
      throw UnsupportedError('Plateforme non supportée');
    }
    return _nativeLib!;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Q26 : permission REQUEST_INSTALL_PACKAGES
  // ─────────────────────────────────────────────────────────────────────

  /// Vrai si AEGIS est autorisé à installer des APK (Paramètres Android).
  static Future<bool> canInstall() async {
    try {
      return await _channel.invokeMethod<bool>('canRequestPackageInstalls') ??
          false;
    } on PlatformException {
      return false;
    }
  }

  /// Ouvre l'écran Android de gestion des sources d'installation.
  static Future<void> openInstallSettings() async {
    try {
      await _channel.invokeMethod('openUnknownSourcesSettings');
    } on PlatformException {
      // Silencieux — l'écran est optionnel.
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // Q22 / C82 : check du manifeste (Tor fetch + FFI Rust ed25519)
  // ─────────────────────────────────────────────────────────────────────

  /// Fetch le manifeste + sa signature via Tor (HTTP-over-Tor), vérifie
  /// ed25519 via Rust, retourne le manifeste parsé si `version > currentVersion`.
  ///
  /// [currentVersion] : version actuelle (ex : '3.1.0').
  ///
  /// Si Tor n'est pas disponible (StrongBox absent, .onion introuvable,
  /// réseau bloqué), retourne `UpdateCheckResult.failure(UpdateRc.torUnavailable)`
  /// ou `torFetchFailed`. Pas de fallback HTTPS (C82 strict).
  static Future<UpdateCheckResult> checkForUpdates({
    required String currentVersion,
  }) async {
    try {
      // 1. Fetch manifest + signature via Tor (FFI Rust)
      final (manifestBytes, sigBytes) = await _fetchManifestViaTor();
      if (manifestBytes == null || sigBytes == null) {
        return UpdateCheckResult.failure(UpdateRc.torFetchFailed);
      }

      // 2. Vérifier la signature ed25519 via Rust
      final rc = _verifyUpdateSignature(manifestBytes, sigBytes);
      if (rc != UpdateRc.ok) {
        return UpdateCheckResult.failure(rc);
      }

      // 3. Parser le JSON (après validation cryptographique)
      final UpdateManifest manifest;
      try {
        final decoded = jsonDecode(utf8.decode(manifestBytes));
        if (decoded is! Map<String, dynamic>) {
          return UpdateCheckResult.failure(UpdateRc.parseError);
        }
        manifest = UpdateManifest(
          version: decoded['version'] as String,
          apkUrl: decoded['apk_url'] as String,
          sha256Hex: decoded['sha256'] as String,
          forceUpdate: decoded['force_update'] as bool? ?? false,
        );
      } catch (_) {
        return UpdateCheckResult.failure(UpdateRc.parseError);
      }

      // 4. Comparer les versions
      if (_isNewerVersion(manifest.version, currentVersion)) {
        return UpdateCheckResult.available(manifest);
      }
      return UpdateCheckResult.upToDate();
    } catch (_) {
      return UpdateCheckResult.failure(UpdateRc.networkError);
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // Q23-Q27 : déclenchement via Kotlin
  // ─────────────────────────────────────────────────────────────────────

  /// Lance le pipeline Kotlin : téléchargement + SHA-256 + Intent.
  ///
  /// Retourne un code [UpdateRc] :
  ///   • `UpdateRc.ok` → Intent d'installation lancé
  ///   • autre → erreur (voir [UpdateRc.describe])
  static Future<int> downloadAndInstall(UpdateManifest manifest) async {
    try {
      final rc = await _channel.invokeMethod<int>('downloadAndInstall', {
        'apkUrl': manifest.apkUrl,
        'expectedSha256Hex': manifest.sha256Hex,
        'version': manifest.version,
      });
      return rc ?? UpdateRc.networkError;
    } on PlatformException catch (e) {
      final details = e.details;
      if (details is int) return details;
      return UpdateRc.networkError;
    }
  }

  /// Stream de progression (émis par Kotlin via `invokeMethod('onProgress')`).
  static Stream<UpdateProgress> get progressStream {
    if (!_reverseHandlerSet) {
      _channel.setMethodCallHandler((call) async {
        if (call.method == 'onProgress') {
          final args = call.arguments;
          if (args is Map) {
            final downloaded = (args['downloaded'] as num?)?.toInt() ?? 0;
            final total = (args['total'] as num?)?.toInt() ?? 0;
            _progressController.add(UpdateProgress(downloaded, total));
          }
        }
        return null;
      });
      _reverseHandlerSet = true;
    }
    return _progressController.stream;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Helpers privés
  // ─────────────────────────────────────────────────────────────────────

  /// Vérifie la signature ed25519 via FFI Rust.
  /// 0 = OK, -60 = signature invalide, -62 = JSON invalide (Rust).
  static int _verifyUpdateSignature(Uint8List manifest, Uint8List signature) {
    final manifestPtr = calloc<Uint8>(manifest.length);
    final sigPtr = calloc<Uint8>(_sigLength);
    final pkPtr = calloc<Uint8>(32);
    try {
      manifestPtr.asTypedList(manifest.length).setAll(0, manifest);
      sigPtr.asTypedList(_sigLength).setAll(0, signature);
      pkPtr.asTypedList(32).setAll(0, _adminPublicKeyBytes);

      final fn = _lib.lookupFunction<_VerifyUpdateSigC, _VerifyUpdateSigDart>(
        'aegis_verify_update_signature',
      );
      return fn(manifestPtr, manifest.length, sigPtr, pkPtr);
    } finally {
      calloc.free(manifestPtr);
      calloc.free(sigPtr);
      calloc.free(pkPtr);
    }
  }

  /// Fetch le manifest + signature via Tor (FFI Rust `aegis_tor_fetch_http`).
  ///
  /// Retourne `(null, null)` si Tor indisponible / fetch échoué.
  /// Les buffers sont alloués une fois (pas d'allocation dynamique itérative).
  static Future<(Uint8List?, Uint8List?)> _fetchManifestViaTor() async {
    final manifestBuf = calloc<Uint8>(_maxManifestBytes);
    final sigBuf = calloc<Uint8>(_sigLength);
    final manifestLen = calloc<IntPtr>();
    final sigLen = calloc<IntPtr>();

    try {
      final fn = _lib.lookupFunction<_TorFetchHttpC, _TorFetchHttpDart>(
        'aegis_tor_fetch_http',
      );

      final rc = fn(manifestBuf, manifestLen, sigBuf, sigLen);

      if (rc != 0) {
        // -2 = Tor indisponible (StrongBox absent)
        // -3 = fetch échoué (réseau, .onion introuvable)
        // -4 = manifest trop gros
        return (null, null);
      }

      final m = Uint8List.fromList(
        manifestBuf.asTypedList(manifestLen.value),
      );
      final s = Uint8List.fromList(
        sigBuf.asTypedList(sigLen.value),
      );
      return (m, s);
    } catch (_) {
      return (null, null);
    } finally {
      calloc.free(manifestBuf);
      calloc.free(sigBuf);
      calloc.free(manifestLen);
      calloc.free(sigLen);
    }
  }

  /// Compare "X.Y.Z" : true si `candidate > current`.
  static bool _isNewerVersion(String candidate, String current) {
    final c = _parseVersion(candidate);
    final r = _parseVersion(current);
    for (var i = 0; i < 3; i++) {
      if (c[i] != r[i]) return c[i] > r[i];
    }
    return false;
  }

  static List<int> _parseVersion(String v) {
    final parts = v.split('.');
    final out = <int>[0, 0, 0];
    for (var i = 0; i < 3 && i < parts.length; i++) {
      out[i] = int.tryParse(parts[i]) ?? 0;
    }
    return out;
  }
}