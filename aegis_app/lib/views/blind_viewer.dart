import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' show compute, debugPrint;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import '../translations.dart';
import '../services/global_state.dart'; // ← FIX 2 : beginExternalFlow/endExternalFlow
import 'camera_capture_screen.dart';

// =========================================================================
// TYPEDEFS FFI
// =========================================================================

typedef NativeIngest       = Int32 Function(Pointer<Utf8>);
typedef DartIngest         = int   Function(Pointer<Utf8>);
typedef NativeVoid         = Void  Function();
typedef DartVoid           = void  Function();
typedef NativeCapture      = Int32 Function();
typedef DartCapture        = int   Function();
typedef NativeIsSurfaceOk  = Int32 Function();
typedef DartIsSurfaceOk    = int   Function();

typedef NativeDecodeBlit   = Int32 Function(Pointer<Utf8>);
typedef DartDecodeBlit     = int   Function(Pointer<Utf8>);
typedef NativeSealRam      = Int32 Function(Pointer<Utf8>);
typedef DartSealRam        = int   Function(Pointer<Utf8>);
typedef NativeHasCapture   = Int32 Function();
typedef DartHasCapture     = int   Function();

// =========================================================================
// FONCTIONS TOP-LEVEL (sendables via `compute`, zéro capture `this`)
// =========================================================================

int _computeApplyPrnu(String destPath) {
  final lib = Platform.isAndroid
      ? DynamicLibrary.open('libaegis_core.so')
      : DynamicLibrary.process();
  final func = lib
      .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>(
          'aegis_apply_prnu_and_save')
      .asFunction<int Function(Pointer<Utf8>)>();
  final pathPtr = destPath.toNativeUtf8();
  try {
    return func(pathPtr);
  } finally {
    malloc.free(pathPtr);
  }
}

int _computeSealRamToDisk(String destPath) {
  final lib = Platform.isAndroid
      ? DynamicLibrary.open('libaegis_core.so')
      : DynamicLibrary.process();
  final func = lib
      .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>(
          'aegis_seal_ram_to_disk')
      .asFunction<int Function(Pointer<Utf8>)>();
  final pathPtr = destPath.toNativeUtf8();
  try {
    return func(pathPtr);
  } finally {
    malloc.free(pathPtr);
  }
}

int _computeSendTor(List<String> args) {
  final lib = Platform.isAndroid
      ? DynamicLibrary.open('libaegis_core.so')
      : DynamicLibrary.process();
  final func = lib
      .lookup<NativeFunction<Int32 Function(Pointer<Utf8>, Pointer<Utf8>)>>(
          'aegis_send_p2p_tor')
      .asFunction<int Function(Pointer<Utf8>, Pointer<Utf8>)>();
  final pathPtr   = args[0].toNativeUtf8();
  final targetPtr = args[1].toNativeUtf8();
  try {
    return func(pathPtr, targetPtr);
  } finally {
    malloc.free(pathPtr);
    malloc.free(targetPtr);
  }
}

int _computeDecodeAndBlit(String filePath) {
  final lib = Platform.isAndroid
      ? DynamicLibrary.open('libaegis_core.so')
      : DynamicLibrary.process();
  final func = lib
      .lookup<NativeFunction<Int32 Function(Pointer<Utf8>)>>(
          'aegis_decode_and_blit_file')
      .asFunction<int Function(Pointer<Utf8>)>();
  final pathPtr = filePath.toNativeUtf8();
  try {
    return func(pathPtr);
  } finally {
    malloc.free(pathPtr);
  }
}

// =========================================================================
// ÉCRAN
// =========================================================================

class BlindViewerScreen extends StatefulWidget {
  final String? initialPath;
  final bool initialRamCapture;

  const BlindViewerScreen({
    super.key,
    this.initialPath,
    this.initialRamCapture = false,
  });

  @override
  State<BlindViewerScreen> createState() => _BlindViewerScreenState();
}

class _BlindViewerScreenState extends State<BlindViewerScreen> {
  String  _statusKey = 'status_ram_empty';
  String? _errorMessage;
  bool    _isIngested = false;
  bool    _isVisualizing = false;
  bool    _isProcessing = false;
  String? _currentInternalPath;
  bool    _isRamCapture = false;

  List<FileSystemEntity> _sandboxFiles = [];

  DynamicLibrary? _aegisLib;
  DartIngest?       _nativeIngest;
  DartVoid?         _nativePurge;
  // Le canal MethodChannel pilote CameraX ; les autres FFI directes
  // (is_surface_ready, decode_and_blit, seal_ram, has_capture) sont
  // appelées via `compute()` avec des lookups top-level — pas besoin
  // de les stocker en champ.
  // ignore: unused_field
  DartCapture?      _nativeCapture;

  final Color _gunmetal   = const Color(0xFF22252A);
  final Color _steel      = const Color(0xFF8D99AE);
  final Color _matteGold  = const Color(0xFFD4AF37);
  final TextStyle _industrialText = const TextStyle(
    fontFamily: 'RobotoMono',
    letterSpacing: 1.5,
    fontWeight: FontWeight.w600,
    fontSize: 10,
  );

  @override
  void initState() {
    super.initState();
    _initFfi();
    _loadSandboxFiles();

    if (widget.initialRamCapture) {
      _isIngested = true;
      _isRamCapture = true;
      _currentInternalPath = null;
      _statusKey = 'status_capture_ready';
      return;
    }

    final p = widget.initialPath;
    if (p != null && p.isNotEmpty) {
      _isIngested = true;
      _isRamCapture = false;
      _currentInternalPath = p;
      _statusKey = 'status_ingested_ready';
    }
  }

  void _initFfi() {
    try {
      _aegisLib = Platform.isAndroid
          ? DynamicLibrary.open('libaegis_core.so')
          : DynamicLibrary.process();

      _nativeIngest = _aegisLib!
          .lookup<NativeFunction<NativeIngest>>('aegis_ingest_file_zero_disk')
          .asFunction();
      _nativePurge = _aegisLib!
          .lookup<NativeFunction<NativeVoid>>('aegis_purge_ram_buffer')
          .asFunction();
      _nativeCapture = _aegisLib!
          .lookup<NativeFunction<NativeCapture>>('aegis_capture_ndk_camera')
          .asFunction();
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Erreur fatale FFI : $e");
    }
  }

  Future<void> _loadSandboxFiles() async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final files = await directory
          .list()
          .where((item) => item.path.toLowerCase().endsWith('.aegis'))
          .toList();
      if (mounted) setState(() => _sandboxFiles = files);
    } catch (e) {
      debugPrint("Erreur sandbox: $e");
    }
  }

  bool get _hasRealPath => _currentInternalPath != null;

  bool get _canPurify =>
      _isIngested && !_isProcessing && (_isRamCapture || _hasRealPath);

  // Q1-ter FIX (2026-09-24) : _formatError i18n (8 clés err_*).
  String _formatError(BuildContext context, String op, int code) {
    switch (code) {
      case -1:  return "$op : ${AppTranslations.get(context, 'err_ptr_null')}";
      case -2:  return "$op : ${AppTranslations.get(context, 'err_path_utf8')}";
      case -3:  return "$op : ${AppTranslations.get(context, 'err_resource_unavailable')}";
      case -4:  return "$op : ${AppTranslations.get(context, 'err_data_corrupted')}";
      case -5:  return "$op : ${AppTranslations.get(context, 'err_vram_not_ready')}";
      case -6:  return "$op : ${AppTranslations.get(context, 'err_disk_write')}";
      case -100:return "$op : ${AppTranslations.get(context, 'err_not_android')}";
      default:  return "$op : ${AppTranslations.get(context, 'err_unknown_code')} ($code)";
    }
  }

  // -------------------------------------------------------------------
  // Bouton CAPTURE NDK — redirection vers l'écran dédié avec aperçu
  // -------------------------------------------------------------------
  //
  // FIX 2 : utilise `beginExternalFlow()` / `endExternalFlow()` au lieu
  // du flag brut `isIntentPendingInDart`. Cela garantit la cohérence
  // même si un flow imbriqué est ajouté plus tard.
  Future<void> _triggerHardwareCapture() async {
    beginExternalFlow();
    try {
      // 1) Demande la permission caméra via permission_handler AVANT
      //    d'ouvrir l'écran de capture.
      var status = await Permission.camera.status;
      if (!status.isGranted) {
        status = await Permission.camera.request();
        if (!status.isGranted) {
          if (mounted) {
            setState(() => _errorMessage = AppTranslations.get(context, 'toast_camera_denied'));
          }
          return;
        }
      }

      if (!mounted) return;

      // 2) Ouvre l'écran de capture avec aperçu LIVE.
      final captured = await Navigator.push<bool>(
        context,
        MaterialPageRoute(
          builder: (context) => const CameraCaptureScreen(),
          fullscreenDialog: true,
        ),
      );

      if (!mounted) return;
      if (captured != true) return;

      // 3) Les frames YUV sont en RAM côté Rust (LAST_CAMERA_FRAME).
      setState(() {
        _isIngested = true;
        _isRamCapture = true;
        _currentInternalPath = null;
        _statusKey = 'status_capture_ready';
        _isVisualizing = false;
        _errorMessage = null;
      });
    } finally {
      endExternalFlow();
    }
  }

  // -------------------------------------------------------------------
  // Bouton DÉPURER : dispatch PRNU (fichier) vs Seal (capture RAM)
  // -------------------------------------------------------------------
  Future<void> _onPurifyPressed() async {
    if (_isRamCapture) {
      return _sealRamToDisk();
    }
    return _applyPrnuAndSave();
  }

  Future<void> _sealRamToDisk() async {
    setState(() {
      _isProcessing = true;
      _statusKey = 'status_purging';
      _errorMessage = null;
    });
    try {
      final directory = await getApplicationDocumentsDirectory();
      final destPath =
          '${directory.path}/aegis_${DateTime.now().millisecondsSinceEpoch}.aegis';

      final res = await compute(_computeSealRamToDisk, destPath);

      if (!mounted) return;
      setState(() {
        if (res == 0) {
          _statusKey = 'status_sealed';
          _isRamCapture = false;
          _currentInternalPath = destPath;
        } else {
          _errorMessage = _formatError(context, "Seal RAM", res);
        }
      });
      await _loadSandboxFiles();
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Crash Seal: $e");
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _applyPrnuAndSave() async {
    if (!_hasRealPath) {
      setState(() {
        _errorMessage = AppTranslations.get(context, 'err_no_real_file');
      });
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusKey = 'status_purging';
      _errorMessage = null;
    });
    try {
      final directory = await getApplicationDocumentsDirectory();
      final destPath =
          '${directory.path}/aegis_${DateTime.now().millisecondsSinceEpoch}.aegis';

      final res = await compute(_computeApplyPrnu, destPath);

      if (!mounted) return;
      setState(() {
        if (res == 0) {
          _statusKey = 'status_sealed';
          _isRamCapture = false;
          _currentInternalPath = destPath;
        } else {
          _errorMessage = _formatError(context, "PRNU", res);
        }
      });
      await _loadSandboxFiles();
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Crash PRNU: $e");
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<void> _visualizeCurrent() async {
    if (!_hasRealPath) {
      setState(() {
        _errorMessage = AppTranslations.get(context, 'err_visualize_needs_file');
      });
      return;
    }

    setState(() => _isVisualizing = true);

    await Future.delayed(const Duration(milliseconds: 500));
    if (!mounted) return;

    final current = _currentInternalPath!;
    int rc = -100;
    try {
      rc = await compute(_computeDecodeAndBlit, current);
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Crash blit: $e");
      return;
    }

    if (rc == -5) {
      await Future.delayed(const Duration(milliseconds: 500));
      if (!mounted) return;
      try {
        rc = await compute(_computeDecodeAndBlit, current);
      } catch (e) {
        if (mounted) setState(() => _errorMessage = "Crash blit (retry): $e");
        return;
      }
    }

    if (!mounted) return;
    if (rc != 0) {
      setState(() => _errorMessage = _formatError(context, "AFFICHER", rc));
    } else {
      setState(() => _errorMessage = null);
    }
  }

  Future<void> _showContactSelectorAndSend() async {
    final selectedContact = await showModalBottomSheet<String>(
      context: context,
      backgroundColor: _gunmetal,
      isScrollControlled: true,
      builder: (BuildContext context) {
        return SafeArea(
          child: Container(
            padding: const EdgeInsets.all(16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(AppTranslations.get(context, 'p2p_select_target'),
                    style: _industrialText.copyWith(color: _steel, fontSize: 12)),
                Divider(color: _steel.withValues(alpha: 0.3)),
                ListTile(
                  leading: Icon(Icons.qr_code_scanner_sharp, color: _steel),
                  title: Text(AppTranslations.get(context, 'p2p_new_contact'),
                      style: _industrialText.copyWith(color: Colors.white)),
                  onTap: () => Navigator.pop(context, "SCAN_NEW"),
                ),
                ListTile(
                  leading: Icon(Icons.security_sharp, color: _matteGold),
                  title: Text(AppTranslations.get(context, 'p2p_contact_alpha'),
                      style: _industrialText.copyWith(color: Colors.white)),
                  subtitle: Text("v23x...onion",
                      style: _industrialText.copyWith(color: _steel, fontSize: 8)),
                  onTap: () => Navigator.pop(context, "v23x_target_onion_address"),
                ),
              ],
            ),
          ),
        );
      },
    );

    if (selectedContact == null) return;

    String? target = selectedContact;
    if (selectedContact == "SCAN_NEW") {
      target = await _openQrScanner();
      if (target == null || target.isEmpty) return;
    }

    final String targetStr = target;

    if (!_hasRealPath) {
      setState(() {
        _errorMessage = AppTranslations.get(context, 'err_tor_needs_sealed');
      });
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusKey = 'status_sending';
      _errorMessage = null;
    });
    try {
      final current = _currentInternalPath!;
      final res = await compute(_computeSendTor, [current, targetStr]);

      if (!mounted) return;
      setState(() {
        if (res == 0) {
          _statusKey = 'status_sent';
        } else {
          _errorMessage = _formatError(context, "ENVOI TOR", res);
        }
      });
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Crash Tor: $e");
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  Future<String?> _openQrScanner() async {
    final completer = Completer<String?>();
    if (!mounted) return null;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.black,
      builder: (ctx) => SizedBox(
        height: 420,
        child: Column(
          children: [
            AppBar(
              title: Text(AppTranslations.get(context, 'scan_qr')),
              backgroundColor: const Color(0xFF1A1C20),
              leading: IconButton(
                icon: Icon(Icons.close, color: _steel),
                onPressed: () {
                  if (!completer.isCompleted) completer.complete(null);
                  Navigator.pop(ctx);
                },
              ),
            ),
            Expanded(
              child: MobileScanner(
                onDetect: (capture) {
                  for (final barcode in capture.barcodes) {
                    if (barcode.rawValue != null) {
                      if (!completer.isCompleted) {
                        completer.complete(barcode.rawValue);
                      }
                      Navigator.pop(ctx);
                      break;
                    }
                  }
                },
              ),
            ),
          ],
        ),
      ),
    );

    return completer.future;
  }

  Future<void> _ingestPath(String filePath) async {
    if (_nativeIngest == null) return;
    setState(() {
      _isProcessing = true;
      _statusKey = 'status_ingesting';
      _errorMessage = null;
    });
    try {
      final pathPtr = filePath.toNativeUtf8();
      int res;
      try {
        res = _nativeIngest!(pathPtr);
      } finally {
        malloc.free(pathPtr);
      }

      if (!mounted) return;
      setState(() {
        if (res == 0) {
          _isIngested = true;
          _isVisualizing = false;
          _isRamCapture = false;
          _currentInternalPath = filePath;
          _statusKey = 'status_ingested_ready';
        } else {
          _errorMessage = _formatError(context, "INGEST", res);
        }
      });
    } catch (e) {
      if (mounted) setState(() => _errorMessage = "Crash FFI Ingestion: $e");
    } finally {
      if (mounted) setState(() => _isProcessing = false);
    }
  }

  void _purge() {
    try {
      _nativePurge?.call();
    } catch (e) {
      debugPrint("Purge native error: $e");
    }
    if (!mounted) return;
    setState(() {
      _isIngested = false;
      _isVisualizing = false;
      _isRamCapture = false;
      _currentInternalPath = null;
      _statusKey = 'status_purged';
      _errorMessage = null;
    });
  }

  @override
  void dispose() {
    _nativeIngest  = null;
    _nativePurge   = null;
    _nativeCapture = null;
    _aegisLib      = null;
    super.dispose();
  }

  // =====================================================================
  // UI
  // =====================================================================

  @override
  Widget build(BuildContext context) {
    final ffiDead = _nativeIngest == null && _errorMessage != null;

    return Scaffold(
      backgroundColor: _gunmetal,
      appBar: AppBar(
        title: Text(AppTranslations.get(context, 'vault_title').toUpperCase(),
            style: _industrialText.copyWith(fontSize: 14)),
        backgroundColor: const Color(0xFF1A1C20),
        iconTheme: IconThemeData(color: _steel),
        elevation: 0,
        actions: [
          if (_isIngested)
            IconButton(
              icon: Icon(Icons.delete_outline_sharp, color: _steel),
              onPressed: _isProcessing ? null : _purge,
            ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              flex: 2,
              child: Container(
                margin: const EdgeInsets.all(12.0),
                decoration: BoxDecoration(
                  border: Border.all(
                    color: _isIngested ? _matteGold : _steel.withValues(alpha: 0.2),
                    width: 1.5,
                  ),
                ),
                child: _isVisualizing && _hasRealPath
                    ? AndroidView(
                        viewType: 'com.aegis.p2p/blind_surface',
                        creationParams: {
                          'filePath': _currentInternalPath,
                          'fromCapture': _isRamCapture,
                        },
                        creationParamsCodec: const StandardMessageCodec(),
                      )
                    : Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            if (_isProcessing)
                              CircularProgressIndicator(
                                  color: _matteGold, strokeWidth: 2)
                            else
                              Icon(
                                Icons.shield_sharp,
                                size: 40,
                                color: _isIngested
                                    ? _matteGold
                                    : _steel.withValues(alpha: 0.3),
                              ),
                            const SizedBox(height: 16),
                            Text(
                              (_isProcessing
                                      ? AppTranslations.get(
                                          context, 'status_op_running')
                                      : (_isIngested
                                          ? AppTranslations.get(
                                              context, 'status_ram_isolated')
                                          : AppTranslations.get(
                                              context, 'status_no_file')))
                                  .toUpperCase(),
                              style: _industrialText.copyWith(color: _steel),
                            ),
                          ],
                        ),
                      ),
              ),
            ),

            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16.0),
              child: Text(
                _errorMessage ??
                    AppTranslations.get(context, _statusKey).toUpperCase(),
                style: _industrialText.copyWith(
                  color: _errorMessage != null ? Colors.redAccent : _matteGold,
                ),
                textAlign: TextAlign.center,
              ),
            ),

            Padding(
              padding: const EdgeInsets.symmetric(vertical: 16.0, horizontal: 8.0),
              child: Wrap(
                alignment: WrapAlignment.center,
                spacing: 8.0,
                runSpacing: 8.0,
                children: [
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        side: BorderSide(color: _steel),
                        foregroundColor: Colors.white),
                    onPressed:
                        (_isProcessing || ffiDead) ? null : _triggerHardwareCapture,
                    icon: const Icon(Icons.camera_alt_sharp, size: 16),
                    label: Text(
                        AppTranslations.get(context, 'btn_capture').toUpperCase(),
                        style: _industrialText),
                  ),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        side: BorderSide(
                            color: _canPurify ? _matteGold : _steel),
                        foregroundColor: Colors.white),
                    onPressed: _canPurify ? _onPurifyPressed : null,
                    icon: const Icon(Icons.blur_on_sharp, size: 16),
                    label: Text(
                        AppTranslations.get(context, 'btn_prnu').toUpperCase(),
                        style: _industrialText),
                  ),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        side: BorderSide(color: _steel),
                        foregroundColor: Colors.white),
                    onPressed: (_isIngested &&
                            _hasRealPath &&
                            !_isVisualizing &&
                            !_isProcessing)
                        ? _visualizeCurrent
                        : null,
                    icon: const Icon(Icons.visibility_sharp, size: 16),
                    label: Text(
                        AppTranslations.get(context, 'btn_vram').toUpperCase(),
                        style: _industrialText),
                  ),
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        side: BorderSide(
                            color: (_isIngested && _hasRealPath && !_isProcessing)
                                ? _matteGold
                                : _steel),
                        foregroundColor: Colors.white),
                    onPressed: (_isIngested && _hasRealPath && !_isProcessing)
                        ? _showContactSelectorAndSend
                        : null,
                    icon: const Icon(Icons.cell_tower_sharp, size: 16),
                    label: Text(
                        AppTranslations.get(context, 'btn_tor').toUpperCase(),
                        style: _industrialText),
                  ),
                ],
              ),
            ),

            Expanded(
              flex: 1,
              child: ListView.builder(
                itemCount: _sandboxFiles.length,
                itemBuilder: (context, index) {
                  final file = _sandboxFiles[index];
                  final fileName = file.path.split('/').last;
                  return ListTile(
                    leading: Icon(Icons.lock_sharp, color: _matteGold, size: 18),
                    title: Text(fileName.toUpperCase(),
                        style: _industrialText.copyWith(color: _steel)),
                    trailing: IconButton(
                      icon: Icon(Icons.download_sharp, color: _steel, size: 18),
                      onPressed: _isProcessing
                          ? null
                          : () => _ingestPath(file.path),
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}