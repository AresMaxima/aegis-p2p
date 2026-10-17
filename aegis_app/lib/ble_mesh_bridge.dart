// aegis_app/lib/ble_mesh_bridge.dart
//
// P0-A.3e.2c (2026-10-17) — Pont Dart ↔ Kotlin (BLE Mesh).
//
// Deux flux :
//   1. MethodChannel `com.aegis/ble_mesh` :
//      Commandes synchrones vers Kotlin (isSupported, initialize, startMesh,
//      stopMesh, startHandshake, handshakeIsComplete, handshakeReset).
//
//   2. EventChannel `com.aegis/ble_mesh_events` :
//      Stream d'événements asynchrones (advertising, connection, cccd,
//      local_delivery, handshake_event).
//
// NE PAS confondre avec wifi_direct_bridge.dart :
//   • WiFi Direct : pont Dart → Kotlin → Rust socket TCP + FFI fingerprint
//   • BLE Mesh    : pont Dart → Kotlin → Rust pipe POSIX (fd).
//
// Les 4 FFI `aegis_ble_handshake_*` (start_initiator, start_responder,
// is_complete, reset) sont appelées DEPUIS Kotlin (BleMeshBridge.kt), pas
// depuis Dart — donc aucun import dart:ffi ici.
//
// Décisions actées :
//   D86 : framing sortant [u8 type][u32 BE len][bytes]
//   D88 : framing entrant [u32 BE len][fragment bytes]
//   D89 (Q18) : handshake en GATT direct (rôle client = initiateur)
//   D90 (Q19) : routage par état (pas de préfixe type wire)
//   D91 (Q20) : timeout handshake 30 s
//   D92 (Q21) : shared_secret = HKDF-SHA256(nonce_i||nonce_r||pubkey_i||pubkey_r)
//   D93 (C66) : close out_fd + reset handshake en fin de reader_loop

import 'dart:async';

import 'package:flutter/services.dart';

// =============================================================================
// Type d'événement BLE Mesh
// =============================================================================

/// Type d'événement reçu du canal `com.aegis/ble_mesh_events`.
enum BleMeshEventType {
  /// Mesh démarré (advertising + GATT server + pipes JNI prêts).
  meshStarted,

  /// Échec du démarrage du mesh (voir `data['error']`).
  meshStartFailed,

  /// Mesh arrêté.
  meshStopped,

  /// Pipes JNI configurés (Rust reader + Kotlin writer démarrés).
  pipesReady,

  /// Advertising BLE démarré.
  advertisingStarted,

  /// Échec du démarrage advertising (voir `data['errorCode']`).
  advertisingFailed,

  /// Peer BLE connecté (voir `data['address']`).
  deviceConnected,

  /// Peer BLE déconnecté (voir `data['address']`).
  deviceDisconnected,

  /// CCCD (Client Characteristic Configuration) modifié.
  /// `data['enabled'] = true` → notifications activées par le peer.
  cccdChanged,

  /// Delivery locale (TTL=0 ou destinataire local).
  /// `data['payload_b64']` = payload MeshFrame sérialisé en Base64.
  localDelivery,

  /// Événement de handshake ed25519 (voir `handshakeEvents`).
  /// `data['status']` = `"complete"` ou `"failed:<code>"`.
  handshakeEvent,

  /// Erreur générique.
  error,

  /// Type inconnu (forward compatibility).
  unknown,
}

/// Événement BLE Mesh reçu de Kotlin.
class BleMeshEvent {
  final BleMeshEventType type;

  /// Champs bruts (dépend du type).
  ///
  /// Exemples :
  ///   • meshStarted          → `{}`
  ///   • meshStartFailed      → `{ "error": "String" }`
  ///   • advertisingFailed    → `{ "errorCode": int }`
  ///   • deviceConnected      → `{ "address": "AA:BB:CC:DD:EE:FF" }`
  ///   • cccdChanged          → `{ "enabled": true }`
  ///   • localDelivery        → `{ "payload_b64": "String" }`
  ///   • handshakeEvent       → `{ "status": "complete" | "failed:-XX" }`
  ///   • error                → `{ "code": String, "message": String }`
  final Map<String, dynamic> data;

  const BleMeshEvent(this.type, this.data);

  /// Parse depuis un Map Kotlin.
  factory BleMeshEvent.fromMap(Map<dynamic, dynamic> raw) {
    final typeStr = raw['type'] as String? ?? 'unknown';
    final type = _typeFromString(typeStr);
    final map = raw.map((k, v) => MapEntry(k.toString(), v));
    return BleMeshEvent(type, map);
  }

  static BleMeshEventType _typeFromString(String s) {
    switch (s) {
      case 'mesh_started':          return BleMeshEventType.meshStarted;
      case 'mesh_start_failed':     return BleMeshEventType.meshStartFailed;
      case 'mesh_stopped':          return BleMeshEventType.meshStopped;
      case 'pipes_ready':           return BleMeshEventType.pipesReady;
      case 'advertising_started':   return BleMeshEventType.advertisingStarted;
      case 'advertising_failed':    return BleMeshEventType.advertisingFailed;
      case 'device_connected':      return BleMeshEventType.deviceConnected;
      case 'device_disconnected':   return BleMeshEventType.deviceDisconnected;
      case 'cccd_changed':          return BleMeshEventType.cccdChanged;
      case 'local_delivery':        return BleMeshEventType.localDelivery;
      case 'handshake_event':       return BleMeshEventType.handshakeEvent;
      case 'error':                 return BleMeshEventType.error;
      default:                      return BleMeshEventType.unknown;
    }
  }

  @override
  String toString() => 'BleMeshEvent($type, $data)';
}

// =============================================================================
// Événement de handshake ed25519
// =============================================================================

/// Statut d'un handshake ed25519 reçu du peer.
enum HandshakeStatus {
  /// Handshake terminé avec succès — session prête.
  complete,

  /// Handshake échoué — voir [BleMeshHandshakeEvent.code].
  failed,
}

/// Événement de handshake ed25519 (payload du canal `com.aegis/ble_mesh_events`
/// avec `type == "handshake_event"`).
class BleMeshHandshakeEvent {
  final HandshakeStatus status;

  /// Code d'erreur Rust (`HandshakeError::to_code`).
  ///
  /// Valeurs courantes :
  ///   -50 = NotStarted
  ///   -51 = AlreadyStarted
  ///   -52 = WrongPhase
  ///   -53 = InvalidLength
  ///   -54 = InvalidSignature
  ///   -55 = FingerprintMismatch
  ///   -56 = CryptoUnavailable
  ///   -57 = Timeout
  ///
  /// `null` si le statut est `complete`.
  final int? code;

  const BleMeshHandshakeEvent({required this.status, this.code});

  /// Parse le champ `status` (`"complete"` ou `"failed:-XX"`).
  ///
  /// Retourne `null` si le format est invalide.
  static BleMeshHandshakeEvent? fromStatusString(String status) {
    if (status == 'complete') {
      return const BleMeshHandshakeEvent(status: HandshakeStatus.complete);
    }
    if (status.startsWith('failed:')) {
      final codeStr = status.substring('failed:'.length);
      final code = int.tryParse(codeStr);
      if (code == null) return null;
      return BleMeshHandshakeEvent(
        status: HandshakeStatus.failed,
        code: code,
      );
    }
    return null;
  }

  /// Message utilisateur court (défaut : anglais). À traduire côté UI si besoin.
  String get message {
    switch (status) {
      case HandshakeStatus.complete:
        return 'Handshake completed — session ready.';
      case HandshakeStatus.failed:
        switch (code) {
          case -53: return 'Invalid message length.';
          case -54: return 'Invalid ed25519 signature.';
          case -55: return 'Fingerprint mismatch (wrong peer or corrupted QR).';
          case -56: return 'Crypto unavailable (vault locked?).';
          case -57: return 'Handshake timeout (30 s).';
          case -51: return 'Handshake already started.';
          case -52: return 'Handshake phase mismatch.';
          default:  return 'Handshake failed (code=$code).';
        }
    }
  }

  @override
  String toString() => 'BleMeshHandshakeEvent($status, code=$code)';
}

// =============================================================================
// BleMeshBridge — façade Dart
// =============================================================================

class BleMeshBridge {
  BleMeshBridge._();

  // ===== Canaux natifs =====

  static const MethodChannel _channel = MethodChannel('com.aegis/ble_mesh');

  static const EventChannel _eventsChannel =
      EventChannel('com.aegis/ble_mesh_events');

  // ===== Stream d'événements (broadcast, écoute native unique) =====

  static final StreamController<BleMeshEvent> _eventController =
      StreamController<BleMeshEvent>.broadcast();

  static bool _nativeEventListenerAttached = false;

  /// Stream des événements BLE Mesh (broadcast, plusieurs listeners OK).
  ///
  /// Le listener natif est attaché au premier accès, une seule fois.
  static Stream<BleMeshEvent> get events {
    _ensureNativeListener();
    return _eventController.stream;
  }

  /// Stream filtré sur les événements de handshake ed25519.
  ///
  /// Émet un [BleMeshHandshakeEvent] par event reçu, avec parsing de
  /// `status` (`complete` ou `failed:<code>`). Les statuts invalides sont
  /// silencieusement ignorés.
  static Stream<BleMeshHandshakeEvent> get handshakeEvents {
    return events
        .where((e) => e.type == BleMeshEventType.handshakeEvent)
        .map((e) {
          final status = e.data['status'] as String? ?? '';
          return BleMeshHandshakeEvent.fromStatusString(status);
        })
        .where((e) => e != null)
        .cast<BleMeshHandshakeEvent>();
  }

  static void _ensureNativeListener() {
    if (_nativeEventListenerAttached) return;
    _nativeEventListenerAttached = true;
    _eventsChannel.receiveBroadcastStream().listen(
      (dynamic raw) {
        if (raw is Map) {
          _eventController.add(BleMeshEvent.fromMap(raw));
        }
      },
      onError: (Object e) {
        _eventController.addError(e);
      },
    );
  }

  // ===========================================================================
  // Commandes MethodChannel
  // ===========================================================================

  /// Vrai si l'hardware supporte BLE.
  static Future<bool> isSupported() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('isSupported');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Initialise le BLE (adapter + advertiser).
  ///
  /// À appeler avant [startMesh].
  static Future<bool> initialize() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('initialize');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Démarre le mesh BLE :
  ///   • GATT server (service + WRITE + NOTIFY avec CCCD)
  ///   • Pipes JNI (Kotlin writer + Rust reader)
  ///   • Advertising adaptatif (LOW_LATENCY → LOW_POWER après 30 s)
  ///
  /// Émet `pipes_ready` puis `advertising_started` sur [events].
  static Future<bool> startMesh() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('startMesh');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Arrête le mesh BLE (advertising, pipes, GATT server).
  ///
  /// Appelle `handshakeReset()` implicitement via Rust (`reader_loop` fait
  /// `ble_handshake::reset()` en sortie, cf. D93/C66).
  static Future<bool> stopMesh() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('stopMesh');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Démarre un handshake ed25519 sur BLE.
  ///
  /// [peerFingerprintB64] : fingerprint SHA-256 de la pubkey ed25519 du peer,
  ///                        encodé en Base64 (32 octets bruts).
  /// [isInitiator] : true = client GATT (envoie Msg1).
  ///                 false = serveur GATT (attend Msg1).
  ///
  /// Le résultat final arrive sur [handshakeEvents] :
  ///   • `complete`      → session prête
  ///   • `failed:<code>` → échec (voir [BleMeshHandshakeEvent.message])
  static Future<bool> startHandshake({
    required String peerFingerprintB64,
    required bool isInitiator,
  }) async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>(
        'startHandshake',
        {
          'peerFingerprintB64': peerFingerprintB64,
          'isInitiator': isInitiator,
        },
      );
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Vrai si le handshake ed25519 est terminé avec succès.
  static Future<bool> handshakeIsComplete() async {
    try {
      final bool? ok =
          await _channel.invokeMethod<bool>('handshakeIsComplete');
      return ok == true;
    } catch (_) {
      return false;
    }
  }

  /// Réinitialise l'état handshake (à appeler sur déconnexion manuelle).
  ///
  /// Note : cette méthode est appelée automatiquement par `stopMesh()`
  /// côté Rust (via D93). À utiliser seulement si l'UI veut forcer un reset
  /// sans arrêter le mesh (ex : "Annuler le pairing").
  static Future<bool> handshakeReset() async {
    try {
      final bool? ok = await _channel.invokeMethod<bool>('handshakeReset');
      return ok == true;
    } catch (_) {
      return false;
    }
  }
}