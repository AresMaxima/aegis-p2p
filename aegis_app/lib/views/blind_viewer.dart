import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import '../main.dart' show isIntentPendingInDart;

typedef NativeIngest = Int32 Function(Pointer<Utf8>);
typedef DartIngest = int Function(Pointer<Utf8>);
typedef NativeVoid = Void Function();
typedef DartVoid = void Function();

const platformLifecycle = MethodChannel('com.example.aegis_app/lifecycle');

Future<void> _setIntentPending(bool pending) async {
  isIntentPendingInDart = pending;
  try {
    await platformLifecycle.invokeMethod('setIntentPending', {'pending': pending});
  } catch (e) {
    debugPrint("Erreur canal lifecycle: $e");
  }
}

class BlindViewerScreen extends StatefulWidget {
  const BlindViewerScreen({super.key});

  @override
  State<BlindViewerScreen> createState() => _BlindViewerScreenState();
}

class _BlindViewerScreenState extends State<BlindViewerScreen> {
  String _status = "RAM Vierge (Non-OS Indexer)";
  bool _isIngested = false;
  bool _isVisualizing = false;

  DynamicLibrary? _aegisLib;
  DartIngest? _nativeIngest;
  DartVoid? _nativePurge;

  @override
  void initState() {
    super.initState();
    _initFfi();
  }

  void _initFfi() {
    try {
      _aegisLib = Platform.isAndroid 
          ? DynamicLibrary.open('libaegis_core.so') 
          : DynamicLibrary.process();
      _nativeIngest = _aegisLib!.lookup<NativeFunction<NativeIngest>>('aegis_ingest_file_zero_disk').asFunction();
      _nativePurge = _aegisLib!.lookup<NativeFunction<NativeVoid>>('aegis_purge_ram_buffer').asFunction();
    } catch (e) {
      debugPrint("Lien FFI aegis-core : $e");
    }
  }

  Future<void> _openLowLevelExplorer() async {
    await _setIntentPending(true);
    try {
      FilePickerResult? result = await FilePicker.pickFiles(
        type: FileType.any,
        allowMultiple: false,
        withData: false,
      );

      if (result != null && result.files.isNotEmpty) {
        // La déclaration correcte avec 'String?' attendue par l'analyseur
        final String? path = result.files.single.path;
        if (path != null && path.isNotEmpty) {
          _ingestPath(path);
        }
      }
    } catch (e) {
      if (mounted) setState(() => _status = "Erreur sélecteur : $e");
    } finally {
      await _setIntentPending(false);
    }
  }

  void _ingestPath(String filePath) async {
    final file = File(filePath);

    try {
      if (!await file.exists()) {
        if (mounted) setState(() => _status = "Erreur : Fichier introuvable");
        return;
      }
      final raf = await file.open(mode: FileMode.read);
      await raf.close();
    } catch (e) {
      if (mounted) setState(() => _status = "Erreur d'accès bas niveau : $e");
      return;
    }

    if (_nativeIngest == null) {
      if (mounted) setState(() => _status = "Erreur FFI : aegis-core non lié");
      return;
    }

    final pathPtr = filePath.toNativeUtf8();
    final int res = _nativeIngest!(pathPtr);
    malloc.free(pathPtr);

    if (mounted) {
      if (res == 0) {
        setState(() {
          _isIngested = true;
          _status = "Verrouillé (mlock) dans aegis-core";
        });
      } else {
        setState(() => _status = "Erreur FFI Ingest : Code $res");
      }
    }
  }

  void _purge() {
    if (_nativePurge != null) _nativePurge!();
    if (mounted) {
      setState(() {
        _isIngested = false;
        _isVisualizing = false;
        _status = "TAMPON PURGÉ (Zeroize)";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    const brandYellow = Color(0xFFFCBE0B);
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("Blind Viewer (VRAM Direct & Non-OS Indexer)"),
        backgroundColor: Colors.grey[900],
        actions: [
          if (_isIngested) IconButton(icon: const Icon(Icons.delete_forever, color: Colors.red), onPressed: _purge),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: Container(
                decoration: BoxDecoration(border: Border.all(color: _isIngested ? brandYellow : Colors.grey[800]!)),
                child: _isVisualizing
                    ? const AndroidView(viewType: 'aegis-blind-view')
                    : Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(Icons.shield, size: 60, color: _isIngested ? brandYellow : Colors.white38),
                            const SizedBox(height: 12),
                            Text(_isIngested ? "Fichier isolé et dépuré en RAM native" : "Aucun fichier en mémoire"),
                          ],
                        ),
                      ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                children: [
                  Text(_status, style: const TextStyle(color: Colors.white70, fontSize: 11), textAlign: TextAlign.center),
                  const SizedBox(height: 12),
                  if (!_isIngested)
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                      onPressed: _openLowLevelExplorer, 
                      icon: const Icon(Icons.sd_storage),
                      label: const Text("EXPLORATEUR BAS NIVEAU (ZERO-DISK)", style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                    )
                  else
                    ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.greenAccent, foregroundColor: Colors.black),
                      onPressed: () => setState(() => _isVisualizing = true),
                      icon: const Icon(Icons.remove_red_eye),
                      label: const Text("AFFICHER SUR SURFACE MATÉRIELLE"),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}