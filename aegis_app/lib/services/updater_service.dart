// aegis_app/lib/services/updater_service.dart
//
// P0-A.8c.2 (2026-10-20) — Couche métier de l'updater in-app.
//
// Orchestre :
//   • checkForUpdates() avec la version courante
//   • Exposition d'un état observable (ChangeNotifier) pour l'UI
//   • Décision : force update (CVE) vs suggestion (feature)
//
// Ne fait AUCUN appel réseau ou natif directement : délègue à
// UpdaterBridge (P0-A.8c.1). L'UI (P0-A.8c.3) consomme cet état.

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../updater_bridge.dart';

/// Cycle de vie d'un check + install.
enum UpdaterState {
  idle,        // rien en cours
  checking,    // fetch manifest en cours
  upToDate,    // à jour
  available,   // mise à jour disponible
  downloading, // APK en cours
  installing,  // Intent lancé
  error,       // échec (voir errorMessage)
}

class UpdaterService extends ChangeNotifier {
  UpdaterService({required this.currentVersion});

  /// Version courante de l'app (ex : '3.1.0'). Fournie par l'UI au boot
  /// (via package_info_plus ou constante hardcodée).
  final String currentVersion;

  UpdaterState _state = UpdaterState.idle;
  UpdateManifest? _manifest;
  UpdateProgress? _progress;
  String? _errorMessage;
  StreamSubscription<UpdateProgress>? _progressSub;

  UpdaterState get state => _state;
  UpdateManifest? get manifest => _manifest;
  UpdateProgress? get progress => _progress;
  String? get errorMessage => _errorMessage;
  bool get hasUpdate => _manifest != null && _state == UpdaterState.available;
  bool get isForceUpdate => _manifest?.forceUpdate ?? false;

  /// Lance un check complet. Idempotent : un check en cours est ignoré.
  Future<void> check() async {
    if (_state == UpdaterState.checking) return;

    _setState(UpdaterState.checking);
    _errorMessage = null;

    final result = await UpdaterBridge.checkForUpdates(
      currentVersion: currentVersion,
    );

    if (result.hasError) {
      _errorMessage = UpdateRc.describe(result.errorRc);
      _setState(UpdaterState.error);
      return;
    }

    if (!result.hasUpdate) {
      _manifest = null;
      _setState(UpdaterState.upToDate);
      return;
    }

    _manifest = result.manifest;
    _setState(UpdaterState.available);
  }

  /// Vérifie que l'installation est autorisée. Si non, ouvre les paramètres
  /// et retourne false. L'utilisateur devra relancer l'update après.
  Future<bool> ensureInstallAllowed() async {
    if (await UpdaterBridge.canInstall()) return true;
    await UpdaterBridge.openInstallSettings();
    return false;
  }

  /// Lance le téléchargement + installation. L'UI doit avoir appelé
  /// [ensureInstallAllowed] avant, ou l'utilisateur a déjà autorisé.
  Future<void> install() async {
    final m = _manifest;
    if (m == null) {
      _errorMessage = 'Aucune mise à jour disponible';
      _setState(UpdaterState.error);
      return;
    }

    if (!await UpdaterBridge.canInstall()) {
      _errorMessage = 'Installation non autorisée — ouvrez les Paramètres';
      _setState(UpdaterState.error);
      return;
    }

    _setState(UpdaterState.downloading);
    _progress = const UpdateProgress(0, 0);
    _errorMessage = null;

    _progressSub?.cancel();
    _progressSub = UpdaterBridge.progressStream.listen((p) {
      _progress = p;
      notifyListeners();
    });

    try {
      final rc = await UpdaterBridge.downloadAndInstall(m);

      if (rc != UpdateRc.ok) {
        _errorMessage = UpdateRc.describe(rc);
        _setState(UpdaterState.error);
        return;
      }

      _setState(UpdaterState.installing);
      // L'installateur système prend le relais. L'app peut être tuée
      // par le système pendant l'install → pas de cleanup ici.
    } finally {
      await _progressSub?.cancel();
      _progressSub = null;
    }
  }

  /// Ignore la mise à jour en cours (sauf si force update).
  /// Retourne true si l'utilisateur peut continuer à utiliser l'app.
  bool dismissUpdate() {
    if (isForceUpdate) return false;
    _manifest = null;
    _state = UpdaterState.upToDate;
    notifyListeners();
    return true;
  }

  void _setState(UpdaterState s) {
    _state = s;
    notifyListeners();
  }

  @override
  void dispose() {
    _progressSub?.cancel();
    _progressSub = null;
    super.dispose();
  }
}