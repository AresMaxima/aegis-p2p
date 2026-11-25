import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

typedef _SetNfcSecretC = Int32 Function(Pointer<Uint8> ptr, IntPtr len);
typedef _SetNfcSecretD = int Function(Pointer<Uint8> ptr, int len);

typedef _ChaffConfigC = Int32 Function(Bool enabled, Uint64 intervalMs);
typedef _ChaffConfigD = int Function(bool enabled, int intervalMs);

typedef _ChaffPollC = Int32 Function(Pointer<Uint8> outCell512Ptr);
typedef _ChaffPollD = int Function(Pointer<Uint8> outCell512Ptr);

typedef _VerifyPeerAttestC = Int32 Function(
  Pointer<Uint8> chainPtr,
  IntPtr chainLen,
  Pointer<Uint8> peerPk32Ptr,
  Pointer<Uint8> nonce32Ptr,
  Bool requireStrongBox,
);
typedef _VerifyPeerAttestD = int Function(
  Pointer<Uint8> chainPtr,
  int chainLen,
  Pointer<Uint8> peerPk32Ptr,
  Pointer<Uint8> nonce32Ptr,
  bool requireStrongBox,
);

typedef _DeadDropDepositC = Int32 Function(
  Pointer<Uint8> blindTag16Ptr,
  Pointer<Uint8> envPtr,
  IntPtr envLen,
);
typedef _DeadDropDepositD = int Function(
  Pointer<Uint8> blindTag16Ptr,
  Pointer<Uint8> envPtr,
  int envLen,
);

typedef _DeadDropCollectC = Int32 Function(
  Pointer<Uint8> recipientPk32Ptr,
  Uint64 epochHour,
  Pointer<Uint8> outBufPtr,
  IntPtr outBufCap,
  Pointer<IntPtr> outWrittenPtr,
);
typedef _DeadDropCollectD = int Function(
  Pointer<Uint8> recipientPk32Ptr,
  int epochHour,
  Pointer<Uint8> outBufPtr,
  int outBufCap,
  Pointer<IntPtr> outWrittenPtr,
);

typedef _OpticalEncodeC = Pointer<Utf8> Function(
  Pointer<Uint8> tid4Ptr,
  Pointer<Uint8> payloadPtr,
  IntPtr payloadLen,
);
typedef _OpticalEncodeD = Pointer<Utf8> Function(
  Pointer<Uint8> tid4Ptr,
  Pointer<Uint8> payloadPtr,
  int payloadLen,
);

typedef _OpticalIngestC = Int32 Function(
  Pointer<Utf8> b64Ptr,
  Pointer<Uint8> outBufPtr,
  IntPtr outBufCap,
  Pointer<IntPtr> outLenPtr,
);
typedef _OpticalIngestD = int Function(
  Pointer<Utf8> b64Ptr,
  Pointer<Uint8> outBufPtr,
  int outBufCap,
  Pointer<IntPtr> outLenPtr,
);

typedef _FreeStringC = Void Function(Pointer<Utf8> ptr);
typedef _FreeStringD = void Function(Pointer<Utf8> ptr);

typedef _WipeV36C = Int32 Function();
typedef _WipeV36D = int Function();

typedef _EdPubkeyC = Int32 Function(Pointer<Uint8> outPk32Ptr);
typedef _EdPubkeyD = int Function(Pointer<Uint8> outPk32Ptr);

typedef _SpqrCheckC = Int32 Function();
typedef _SpqrCheckD = int Function();
typedef _StealthWrapC = Int32 Function(Pointer<Uint8> k, Pointer<Uint8> c, Pointer<Uint8> o, IntPtr cap, Pointer<IntPtr> w);
typedef _StealthWrapD = int Function(Pointer<Uint8> k, Pointer<Uint8> c, Pointer<Uint8> o, int cap, Pointer<IntPtr> w);
typedef _StealthUnwrapC = Int32 Function(Pointer<Uint8> k, Pointer<Uint8> w, IntPtr wlen, Pointer<Uint8> out512);
typedef _StealthUnwrapD = int Function(Pointer<Uint8> k, Pointer<Uint8> w, int wlen, Pointer<Uint8> out512);

class V36HardeningBridge {
  static final ValueNotifier<bool> stealthMasqueActive = ValueNotifier<bool>(false);
  static final ValueNotifier<int> spqrEpochCount = ValueNotifier<int>(0);
  V36HardeningBridge._();

  static const MethodChannel _keystoreChannel = MethodChannel('com.aegis/keystore');
  static DynamicLibrary? _libCache;
  static Timer? _chaffTimer;

  static final ValueNotifier<bool> chaffActive = ValueNotifier<bool>(false);
  static final ValueNotifier<int> chaffCellsEmitted = ValueNotifier<int>(0);
  static final ValueNotifier<bool> nfcTokenSealed = ValueNotifier<bool>(false);
  static final ValueNotifier<bool> mutualAttestRequired = ValueNotifier<bool>(true);

  static DynamicLibrary get _lib {
    if (_libCache != null) return _libCache!;
    if (!Platform.isAndroid) {
      throw UnsupportedError('Android ARM64 requis');
    }
    _libCache = DynamicLibrary.open('libaegis_core.so');
    return _libCache!;
  }

  static Uint8List? getOwnEd25519PublicKey() {
    final ptr = calloc<Uint8>(32);
    try {
      final fn = _lib.lookupFunction<_EdPubkeyC, _EdPubkeyD>('aegis_ed25519_public_key');
      final rc = fn(ptr);
      if (rc != 0) return null;
      return Uint8List.fromList(ptr.asTypedList(32));
    } catch (_) {
      return null;
    } finally {
      calloc.free(ptr);
    }
  }

  /// C90 : Active/desactive le flux continu de cellules factices 512 octets.
  static bool configureChaffing({required bool enabled, int intervalMs = 1000}) {
    try {
      final fn = _lib.lookupFunction<_ChaffConfigC, _ChaffConfigD>('aegis_chaff_configure');
      final rc = fn(enabled, intervalMs);
      if (rc != 0) return false;
      _chaffTimer?.cancel();
      chaffActive.value = enabled;
      if (enabled) {
        _chaffTimer = Timer.periodic(Duration(milliseconds: intervalMs), (_) {
          final cell = pollChaffCell512();
          if (cell != null && cell.length == 512) {
            chaffCellsEmitted.value = chaffCellsEmitted.value + 1;
          }
        });
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  static Uint8List? pollChaffCell512() {
    final outPtr = calloc<Uint8>(512);
    try {
      final fn = _lib.lookupFunction<_ChaffPollC, _ChaffPollD>('aegis_chaff_poll_cell');
      final kind = fn(outPtr);
      if (kind < 0) return null;
      return Uint8List.fromList(outPtr.asTypedList(512));
    } catch (_) {
      return null;
    } finally {
      calloc.free(outPtr);
    }
  }

  /// C91 : Genere localement la chaine X.509 StrongBox liee au pair et verifie via Rust.
  static Future<Uint8List?> generateOwnPeerAttestation(Uint8List peerPk32, Uint8List nonce32) async {
    try {
      return await _keystoreChannel.invokeMethod<Uint8List>(
        'generatePeerAttestationChain',
        {'peerEd25519Pk': peerPk32, 'sessionNonce': nonce32},
      );
    } catch (_) {
      return null;
    }
  }

  static int verifyPeerAttestation({
    required Uint8List derChain,
    required Uint8List peerEd25519Pk32,
    required Uint8List sessionNonce32,
    bool requireStrongBox = false,
  }) {
    if (derChain.isEmpty || peerEd25519Pk32.length != 32 || sessionNonce32.length != 32) {
      return -1;
    }
    final chainPtr = calloc<Uint8>(derChain.length);
    final pkPtr = calloc<Uint8>(32);
    final noncePtr = calloc<Uint8>(32);
    try {
      chainPtr.asTypedList(derChain.length).setAll(0, derChain);
      pkPtr.asTypedList(32).setAll(0, peerEd25519Pk32);
      noncePtr.asTypedList(32).setAll(0, sessionNonce32);
      final fn = _lib.lookupFunction<_VerifyPeerAttestC, _VerifyPeerAttestD>('aegis_verify_peer_attestation');
      return fn(chainPtr, derChain.length, pkPtr, noncePtr, requireStrongBox);
    } catch (_) {
      return -99;
    } finally {
      calloc.free(chainPtr);
      calloc.free(pkPtr);
      calloc.free(noncePtr);
    }
  }

  /// C92 : Encode un message/fichier en gouttes Fountain QR (Luby Transform 0-RF).
  static List<String> encodeOpticalFountainFrames(Uint8List payload) {
    if (payload.isEmpty) return const [];
    final rng = Random.secure();
    final tidPtr = calloc<Uint8>(4);
    final payPtr = calloc<Uint8>(payload.length);
    Pointer<Utf8> jsonPtr = nullptr;
    try {
      for (int i = 0; i < 4; i++) {
        tidPtr[i] = rng.nextInt(256);
      }
      payPtr.asTypedList(payload.length).setAll(0, payload);
      final encFn = _lib.lookupFunction<_OpticalEncodeC, _OpticalEncodeD>('aegis_optical_encode_json');
      jsonPtr = encFn(tidPtr, payPtr, payload.length);
      if (jsonPtr == nullptr) return const [];
      final jsonStr = jsonPtr.toDartString();
      final decoded = jsonDecode(jsonStr) as List<dynamic>;
      return decoded.cast<String>();
    } catch (_) {
      return const [];
    } finally {
      if (jsonPtr != nullptr) {
        try {
          final freeFn = _lib.lookupFunction<_FreeStringC, _FreeStringD>('aegis_free_string');
          freeFn(jsonPtr);
        } catch (_) {}
      }
      calloc.free(tidPtr);
      calloc.free(payPtr);
    }
  }

  /// C92 : Ingere un QR code Fountain scanne en Mode Avion. Retourne les octets une fois reconstruit.
  static ({int status, Uint8List? data}) ingestOpticalDroplet(String b64Droplet) {
    final cStr = b64Droplet.toNativeUtf8();
    const int cap = 256 * 1024;
    final outPtr = calloc<Uint8>(cap);
    final lenPtr = calloc<IntPtr>(1);
    try {
      final fn = _lib.lookupFunction<_OpticalIngestC, _OpticalIngestD>('aegis_optical_ingest_droplet');
      final rc = fn(cStr, outPtr, cap, lenPtr);
      if (rc == 1) {
        final n = lenPtr.value;
        return (status: 1, data: Uint8List.fromList(outPtr.asTypedList(n)));
      }
      return (status: rc, data: null);
    } catch (_) {
      return (status: -99, data: null);
    } finally {
      calloc.free(cStr);
      calloc.free(outPtr);
      calloc.free(lenPtr);
    }
  }

  /// C93 : Depose une enveloppe aveugle dans le coffre circulaire RAM Dead-Drop.
  static bool depositBlindDeadDrop(Uint8List blindTag16, Uint8List envelope) {
    if (blindTag16.length != 16 || envelope.isEmpty) return false;
    final tagPtr = calloc<Uint8>(16);
    final envPtr = calloc<Uint8>(envelope.length);
    try {
      tagPtr.asTypedList(16).setAll(0, blindTag16);
      envPtr.asTypedList(envelope.length).setAll(0, envelope);
      final fn = _lib.lookupFunction<_DeadDropDepositC, _DeadDropDepositD>('aegis_deaddrop_deposit');
      return fn(tagPtr, envPtr, envelope.length) == 0;
    } catch (_) {
      return false;
    } finally {
      calloc.free(tagPtr);
      calloc.free(envPtr);
    }
  }

  /// C93 : Collecte destructive (Read-Once & Burn) des enveloppes sur la fenetre horaire courante.
  static List<Uint8List> collectOwnDeadDrops(Uint8List ownEd25519Pk32) {
    if (ownEd25519Pk32.length != 32) return const [];
    final epochHour = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 3600000;
    const int cap = 128 * 1024;
    final pkPtr = calloc<Uint8>(32);
    final outPtr = calloc<Uint8>(cap);
    final writtenPtr = calloc<IntPtr>(1);
    try {
      pkPtr.asTypedList(32).setAll(0, ownEd25519Pk32);
      final fn = _lib.lookupFunction<_DeadDropCollectC, _DeadDropCollectD>('aegis_deaddrop_collect_and_burn');
      final count = fn(pkPtr, epochHour, outPtr, cap, writtenPtr);
      if (count <= 0) return const [];
      final totalBytes = writtenPtr.value;
      final raw = outPtr.asTypedList(totalBytes);
      final results = <Uint8List>[];
      int off = 0;
      while (off + 4 <= totalBytes) {
        final itemLen = (raw[off] << 24) | (raw[off + 1] << 16) | (raw[off + 2] << 8) | raw[off + 3];
        off += 4;
        if (off + itemLen > totalBytes) break;
        results.add(Uint8List.fromList(raw.sublist(off, off + itemLen)));
        off += itemLen;
      }
      return results;
    } catch (_) {
      return const [];
    } finally {
      calloc.free(pkPtr);
      calloc.free(outPtr);
      calloc.free(writtenPtr);
    }
  }

  /// C94 : Scelle l'identite Ed25519 avec un jeton materiel externe NFC (YubiKey 5 NFC).
  static Future<bool> enrollExternalNfcToken() async {
    final rng = Random.secure();
    final challenge = Uint8List.fromList(List<int>.generate(32, (_) => rng.nextInt(256)));
    try {
      final Uint8List? derived = await _keystoreChannel.invokeMethod<Uint8List>(
        'enrollNfcHardwareToken',
        {'challenge': challenge},
      );
      if (derived == null || derived.length != 32) return false;
      final ptr = calloc<Uint8>(32);
      try {
        ptr.asTypedList(32).setAll(0, derived);
        final fn = _lib.lookupFunction<_SetNfcSecretC, _SetNfcSecretD>('aegis_set_external_nfc_token_secret');
        final ok = fn(ptr, 32) == 0;
        if (ok) nfcTokenSealed.value = true;
        return ok;
      } finally {
        ptr.asTypedList(32).fillRange(0, 32, 0);
        calloc.free(ptr);
      }
    } catch (_) {
      return false;
    }
  }

  static void clearExternalNfcToken() {
    try {
      final fn = _lib.lookupFunction<_SetNfcSecretC, _SetNfcSecretD>('aegis_set_external_nfc_token_secret');
      fn(nullptr, 0);
      nfcTokenSealed.value = false;
    } catch (_) {}
  }

  static void wipeAllEphemeralV36() {
    _chaffTimer?.cancel();
    chaffActive.value = false;
    nfcTokenSealed.value = false;
    try {
      final fn = _lib.lookupFunction<_WipeV36C, _WipeV36D>('aegis_v36_wipe_ephemeral_buffers');
      fn();
    } catch (_) {}
  }
  /// C95 : Execute un re-encapsulage ML-KEM-1024 continu (4x512B) et verifie l'aveuglement PCS.
  static int runSpqrPcsEpochSelfCheck() {
    try {
      final fn = _lib.lookupFunction<_SpqrCheckC, _SpqrCheckD>('aegis_spqr_run_pcs_epoch_selfcheck');
      final rc = fn();
      if (rc > 0) spqrEpochCount.value = rc;
      return rc;
    } catch (_) { return -99; }
  }

  /// C96 : Encapsule/desencapsule une cellule 512B en capsule HTTP/3 MASQUE + GREASE anti-DPI.
  static int testStealthMasqueRoundtrip() {
    final k = calloc<Uint8>(32); final c = calloc<Uint8>(512);
    final o = calloc<Uint8>(768); final r = calloc<Uint8>(512); final w = calloc<IntPtr>(1);
    try {
      final rng = Random.secure();
      for (int i = 0; i < 32; i++) { k[i] = rng.nextInt(256); }
      for (int i = 0; i < 512; i++) { c[i] = rng.nextInt(256); }
      final wrap = _lib.lookupFunction<_StealthWrapC, _StealthWrapD>('aegis_stealth_wrap_h3_cell');
      final unwrap = _lib.lookupFunction<_StealthUnwrapC, _StealthUnwrapD>('aegis_stealth_unwrap_h3_cell');
      if (wrap(k, c, o, 768, w) != 0) return -1;
      if (unwrap(k, o, w.value, r) != 0) return -2;
      for (int i = 0; i < 512; i++) { if (c[i] != r[i]) return -3; }
      return w.value;
    } catch (_) { return -99; } finally {
      calloc.free(k); calloc.free(c); calloc.free(o); calloc.free(r); calloc.free(w);
    }
  }
}
