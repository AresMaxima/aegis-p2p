// aegis_app/lib/wifi_direct_bridge.dart
//
// P0-A.2b.4 (2026-10-11) — Pont Dart ↔ Kotlin (Wi-Fi Direct) ↔ Rust.
//
// Trois flux :
//   1. MethodChannel `com.aegis/wifi_direct` :
//      Commandes synchrones vers Kotlin (isSupported, getEphemeralName,
//      getEphemeralPort, startDiscovery, connectToPeer, disconnect, closeFd).
//
//   2. EventChannel `com.aegis/wifi_direct_events` :
//      Stream d'événements asynchrones (peers, connection, timeout).
//
//   3. FFI Rust direct :
//      `aegis_ed25519_fingerprint` (SHA-256 de la pubkey ed25519 du device).
//      Appel direct car la fingerprint n'est pas un secret (public par design,
//      destinée au QR code). Cohérent avec keystore_bridge.dart qui appelle
//      déjà les FFI Rust `aegis_vault_*` directement.
//
// Format du QR code (D3, validé session 3.22) :
//   AEGIS-WD:<deviceName_12chars>:<port_décimal>:<fingerprint_hex_64chars>
//
//   • Préfixe  : "AEGIS-WD:" (identifie le type)
//   • deviceName : 12 chars base62 (A-Za-z0-9)
//   • port     : 1-5 chiffres (port TCP Wi-Fi Direct)
//   • fingerprint : 64 chars hex (32 octets SHA-256 de la pubkey)
//
//   Total ≈ 90 chars. Scanner-friendly, non-ambigu (pas de ':' dans
//   les sous-champs).

import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';

// =============================================================================
// FFI Rust — aegis_ed25519_fingerprint
// =============================================================================

typedef _AegisEd25519FingerprintC = Int32 Function(Pointer<Uint8> outPtr);
typedef _AegisEd25519FingerprintDart = int Function(Pointer<Uint8> outPtr);

// =============================================================================
// Type d'événement Wi-Fi Direct
// =============================================================================

/// Type d'événement reçu du canal `com.aegis/wifi_direct_events`.
enum WifiDirectEventType {
  /// État Wi-Fi Direct activé/désactivé (Wi-Fi toggle par l'utilisateur).
  stateChanged,

  /// Liste des peers AEGIS visibles (après filtrage deviceName).
  peersAvailable,

  /// Découverte démarrée avec succès.
  discoveryStarted,

  /// Échec du démarrage de la découverte.
  discoveryFailed,

  /// Découverte stoppée.
  discoveryStopped,

  /// Timeout de la découverte (40 s par défaut).
  discoveryTimeout,

  /// Connexion Wi-Fi Direct initiée vers un peer.
  connecting,

  /// Échec de la connexion.
  connectFailed,

  /// Groupe Wi-Fi Direct formé (peer authentifié au niveau Wi-Fi).
  connected,

  /// Déconnexion.
  disconnected,

  /// Échec de la déconnexion.
  disconnectFailed,

  /// Socket TCP transmis à Rust avec succès.
  socketReady,

  /// Erreur socket.
  socketError,

  /// Erreur générique.
  error,

  /// Type inconnu (forward compatibility).
  unknown,
}

/// Événement Wi-Fi Direct reçu de Kotlin.
class WifiDirectEvent {
  final WifiDirectEventType type;

  /// Champs bruts (dépend du type).
  ///
  /// Exemples :
  ///   • stateChanged        → `{ "enabled": true }`
  ///   • peersAvailable      → `{ "peers": [{...}, ...] }`
  ///   • discoveryFailed     → `{ "reason": int }`
  ///   • connected           → `{ "isGroupOwner": bool, "groupOwnerAddress": String? }`
  ///   • socketReady         → `{ "role": String }`
  ///   • error               → `{ "code": String, "message": String }`
  final Map<String, dynamic> data;

  const WifiDirectEvent(this.type, this.data);

  /// Parse depuis un Map Kotlin.
  factory WifiDirectEvent.fromMap(Map<dynamic, dynamic> raw) {
    final typeStr = raw['type'] as String? ?? 'unknown';
    final type = _typeFromString(typeStr);
    final map = raw.map((k, v) => MapEntry(k.toString(), v));
    return WifiDirectEvent(type, map);
  }

  static WifiDirectEventType _typeFromString(String s) {
    switch (s) {
      case 'state_changed':       return WifiDirectEventType.stateChanged;
      case 'peers_available':     return WifiDirectEventType.peersAvailable;
      case 'discovery_started':   return WifiDirectEventType.discoveryStarted;
      case 'discovery_failed':    return WifiDirectEventType.discoveryFailed;
      case 'discovery_stopped':   return WifiDirectEventType.discoveryStopped;
      case 'discovery_timeout':   return WifiDirectEventType.discoveryTimeout;
      case 'connecting':          return WifiDirectEventType.connecting;
      case 'connect_failed':      return WifiDirectEventType.connectFailed;
      case 'connected':           return WifiDirectEventType.connected;
      case 'disconnected':        return WifiDirectEventType.disconnected;
      case 'disconnect_failed':   return WifiDirectEventType.disconnectFailed;
      case 'socket_ready':        return WifiDirectEventType.socketReady;
      case 'socket_error':        return WifiDirectEventType.socketError;
      case 'error':               return WifiDirectEventType.error;
      default:                    return WifiDirectEventType.unknown;
    }
  }

  @override
  String toString() => 'WifiDirectEvent($type, $data)';
}

// =============================================================================
// WifiDirectBridge — façade Dart
// =============================================================================

class WifiDirectBridge {
  WifiDirectBridge._();

  // ===== Canaux natifs =====

  static const MethodChannel _channel =
      MethodChannel('com.aegis/wifi_direct');

  static const EventChannel _eventsChannel =
      EventChannel('com.aegis/wifi_direct_events');

  // ===== FFI Rust =====

  static DynamicLibrary? _nativeLib;

  static DynamicLibrary get _lib {
    if (_nativeLib != null) return _nativeLib!;
    if (Platform.isAndroid) {
      _nativeLib = DynamicLibrary.open('libaegis_core.so');
    } else {
      throw UnsupportedError('Wi-Fi Direct bridge supporté uniquement sur Android');
    }
    return _nativeLib!;
  }

  // ===== Stream d'événements (broadcast, écoute native unique) =====

  static final StreamController<WifiDirectEvent> _eventController =
      StreamController<WifiDirectEvent>.broadcast();

  static bool _nativeEventListenerAttached = false;

  /// Stream des événements Wi-Fi Direct (broadcast, plusieurs listeners OK).
  ///
  /// Le listener natif est attaché au premier accès, une seule fois.
  static Stream<WifiDirectEvent> get events {
    if (!_nativeEventListenerAttached) {
      _nativeEventListenerAttached = true;
      _eventsChannel.receiveBroadcastStream().listen(
        (dynamic raw) {
          if (raw is Map) {
            _eventController.add(WifiDirectEvent.fromMap(raw));
          }
        },
        onError: (Object e) {
          _eventController.addError(e);
        },
      );
    }
    return _eventController.stream;
  }

  // ===========================================================================
  // Commandes MethodChannel
  // ===========================================================================

  /// Vrai si l'hardware supporte Wi-Fi Direct.
  static Future<bool> isSupported() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('isSupported');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Nom éphémère courant (12 chars base62).
  ///
  /// `null` si le bridge n'est pas initialisé.
  static Future<String?> getEphemeralName() async {
    try {
      return await _channel.invokeMethod<String>('getEphemeralName');
    } catch (_) {
      return null;
    }
  }

  /// Port TCP d'écoute local (inclus dans le QR code).
  ///
  /// Retourne `0` si le bridge n'est pas initialisé.
  static Future<int> getEphemeralPort() async {
    try {
      final int? p = await _channel.invokeMethod<int>('getEphemeralPort');
      return p ?? 0;
    } catch (_) {
      return 0;
    }
  }

  /// État actuel du bridge.
  ///
  /// Contient : `supported`, `initialized`, `wifi_p2p_enabled`, `discovery_active`.
  static Future<Map<String, dynamic>> getState() async {
    try {
      final Map<dynamic, dynamic>? m =
          await _channel.invokeMethod<Map<dynamic, dynamic>>('getState');
      if (m == null) return {};
      return m.map((k, v) => MapEntry(k.toString(), v));
    } catch (_) {
      return {};
    }
  }

  /// Démarre une découverte ciblée (deviceName attendu).
  ///
  /// Retourne `true` si la découverte a été lancée.
  static Future<bool> startDiscovery(String expectedName) async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>(
        'startDiscovery',
        {'deviceName': expectedName},
      );
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Arrête la découverte en cours.
  static Future<bool> stopDiscovery() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('stopDiscovery');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Se connecte à un peer (deviceName + port issus du QR code).
  ///
  /// Le port est transmis à Kotlin qui l'utilisera pour ouvrir le socket.
  static Future<bool> connectToPeer({
    required String deviceName,
    required int peerPort,
  }) async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>(
        'connectToPeer',
        {
          'deviceName': deviceName,
          'peerPort': peerPort,
        },
      );
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Déconnecte du peer actif.
  static Future<bool> disconnect() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('disconnect');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Ferme le fd côté Rust (déconnexion complète).
  static Future<bool> closeFd() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('closeFd');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  // ===========================================================================
  // FFI Rust — fingerprint ed25519
  // ===========================================================================

  /// Retourne la fingerprint SHA-256 de la pubkey ed25519 du device.
  ///
  /// Retourne `null` si la master_key n'est pas disponible (vault verrouillé).
  static Uint8List? getFingerprint() {
    final ptr = calloc<Uint8>(32);
    try {
      final fn = _lib.lookupFunction<
          _AegisEd25519FingerprintC, _AegisEd25519FingerprintDart>(
        'aegis_ed25519_fingerprint',
      );
      final rc = fn(ptr);
      if (rc != 0) return null;
      return Uint8List.fromList(ptr.asTypedList(32));
    } catch (_) {
      return null;
    } finally {
      calloc.free(ptr);
    }
  }

  /// Fingerprint en hex (64 chars minuscules).
  ///
  /// `null` si la master_key n'est pas disponible.
  static String? getFingerprintHex() {
    final fp = getFingerprint();
    if (fp == null) return null;
    return fp.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  // ===========================================================================
  // QR code — génération et parsing
  // ===========================================================================

  /// Construit le payload QR :
  ///
  /// ```
  /// AEGIS-WD:<deviceName>:<port>:<fingerprint_hex>
  /// ```
  ///
  /// Retourne `null` si deviceName, port ou fingerprint indisponibles.
  static Future<String?> buildQrPayload() async {
    final name = await getEphemeralName();
    final port = await getEphemeralPort();
    final fp = getFingerprintHex();

    if (name == null || name.isEmpty) return null;
    if (port <= 0 || port > 65535) return null;
    if (fp == null || fp.length != 64) return null;

    return 'AEGIS-WD:$name:$port:$fp';
  }

  /// Parse un payload QR scanné.
  ///
  /// Retourne `null` si le format est invalide.
  static WifiDirectQrPayload? parseQrPayload(String raw) {
    final parts = raw.split(':');
    if (parts.length != 4) return null;
    if (parts[0] != 'AEGIS-WD') return null;

    final deviceName = parts[1];
    if (deviceName.length != 12) return null;
    if (!RegExp(r'^[A-Za-z0-9]{12}$').hasMatch(deviceName)) return null;

    final port = int.tryParse(parts[2]);
    if (port == null || port <= 0 || port > 65535) return null;

    final fpHex = parts[3];
    if (fpHex.length != 64) return null;
    if (!RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(fpHex)) return null;

    return WifiDirectQrPayload(
      deviceName: deviceName,
      port: port,
      fingerprintHex: fpHex.toLowerCase(),
    );
  }
}

/// Contenu structuré d'un QR code AEGIS-WD.
class WifiDirectQrPayload {
  final String deviceName;
  final int port;
  final String fingerprintHex;

  const WifiDirectQrPayload({
    required this.deviceName,
    required this.port,
    required this.fingerprintHex,
  });

  /// Fingerprint en bytes (32 octets).
  Uint8List fingerprintBytes() {
    final out = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      out[i] = int.parse(
        fingerprintHex.substring(i * 2, i * 2 + 2),
        radix: 16,
      );
    }
    return out;
  }

  @override
  String toString() => 'WifiDirectQrPayload($deviceName:$port:${fingerprintHex.substring(0, 8)}...)';
}