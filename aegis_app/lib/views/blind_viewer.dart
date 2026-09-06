import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

// Déclarations FFI (Phases 3 et 4 - Protocole BRAVO)
typedef NativeIngest = Int32 Function(Pointer<Utf8>);
typedef DartIngest = int Function(Pointer<Utf8>);

typedef NativeVoid = Void Function();
typedef DartVoid = void Function();

typedef NativeCapture = Int32 Function();
typedef DartCapture = int Function();

typedef NativePrnuSave = Int32 Function(Pointer<Utf8>);
typedef DartPrnuSave = int Function(Pointer<Utf8>);

typedef NativeSendTor = Int32 Function(Pointer<Utf8>);
typedef DartSendTor = int Function(Pointer<Utf8>);

class BlindViewerScreen extends StatefulWidget {
  const BlindViewerScreen({super.key});

  @override
  State<BlindViewerScreen> createState() => _BlindViewerScreenState();
}

class _BlindViewerScreenState extends State<BlindViewerScreen> {
  String _status = "RAM Vierge (Non-OS Indexer)";
  bool _isIngested = false;
  bool _isVisualizing = false;
  String? _currentInternalPath;
  List<FileSystemEntity> _sandboxFiles = [];

  DynamicLibrary? _aegisLib;
  DartIngest? _nativeIngest;
  DartVoid? _nativePurge;
  DartCapture? _nativeCapture;
  DartPrnuSave? _nativePrnuSave;
  DartSendTor? _nativeSendTor;

  @override
  void initState() {
    super.initState();
    _initFfi();
    _loadSandboxFiles();
  }

  void _initFfi() {
    try {
      _aegisLib = Platform.isAndroid ? DynamicLibrary.open('libaegis_core.so') : DynamicLibrary.process();
      _nativeIngest = _aegisLib!.lookup<NativeFunction<NativeIngest>>('aegis_ingest_file_zero_disk').asFunction();
      _nativePurge = _aegisLib!.lookup<NativeFunction<NativeVoid>>('aegis_purge_ram_buffer').asFunction();
      _nativeCapture = _aegisLib!.lookup<NativeFunction<NativeCapture>>('aegis_capture_ndk_camera').asFunction();
      _nativePrnuSave = _aegisLib!.lookup<NativeFunction<NativePrnuSave>>('aegis_apply_prnu_and_save').asFunction();
      _nativeSendTor = _aegisLib!.lookup<NativeFunction<NativeSendTor>>('aegis_send_p2p_tor').asFunction();
    } catch (e) {
      debugPrint("Lien FFI aegis-core : $e");
    }
  }

  // EXPLORATEUR INTERNE 100% FLUTTER (Bypass Total de l'OS)
  Future<void> _loadSandboxFiles() async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      if (mounted) {
        setState(() {
          _sandboxFiles = directory.listSync().where((item) => item.path.endsWith('.aegis')).toList();
        });
      }
    } catch (e) {
      debugPrint("Erreur lecture sandbox: $e");
    }
  }

  // 1. CAPTURE FURTIVE (NDK)
  void _triggerHardwareCapture() {
    if (_nativeCapture == null) return;
    setState(() => _status = "Capture NDK en cours... (Zero-Disk)");
    
    final res = _nativeCapture!();
    
    if (mounted) {
      if (res == 0) {
        setState(() {
          _isIngested = true;
          _currentInternalPath = null; // C'est une nouvelle capture pure RAM
          _isVisualizing = false;
          _status = "Capture brute en RAM. Prêt pour dépuration.";
        });
      } else {
        setState(() => _status = "Erreur Capture NDK : $res");
      }
    }
  }

  // 2. DÉPURATION PRNU & SCELLEMENT
  void _applyPrnuAndSave() async {
    if (_nativePrnuSave == null) return;
    setState(() => _status = "Application Filtre PRNU 3x3 & Stripping EXIF...");
    
    // Génération automatique du chemin Sandbox pour la sauvegarde
    final directory = await getApplicationDocumentsDirectory();
    final String destPath = '${directory.path}/aegis_${DateTime.now().millisecondsSinceEpoch}.aegis';
    
    final pathPtr = destPath.toNativeUtf8();
    final res = _nativePrnuSave!(pathPtr);
    malloc.free(pathPtr);

    if (mounted) {
      if (res == 0) {
        setState(() {
          _status = "Média anonymisé et scellé avec succès (.aegis).";
          _currentInternalPath = destPath; // Le fichier existe désormais sur disque Sandbox
        });
        _loadSandboxFiles();
      } else {
        setState(() => _status = "Erreur PRNU/Scellement : $res");
      }
    }
  }

  // 3. EXPÉDITION P2P
  void _sendOverTor() {
    if (_nativeSendTor == null || _currentInternalPath == null) return;
    setState(() => _status = "Découpage (512B) & Envoi Tor v3 en cours...");
    
    final pathPtr = _currentInternalPath!.toNativeUtf8();
    final res = _nativeSendTor!(pathPtr);
    malloc.free(pathPtr);

    if (mounted) {
      if (res == 0) {
        setState(() => _status = "Expédition P2P terminée.");
      } else {
        setState(() => _status = "Erreur Envoi Tor : $res");
      }
    }
  }

  // INGESTION DEPUIS LA SANDBOX INTERNE
  void _ingestPath(String filePath) {
    if (_nativeIngest == null) return;
    final pathPtr = filePath.toNativeUtf8();
    final int res = _nativeIngest!(pathPtr);
    malloc.free(pathPtr);

    if (res == 0) {
      setState(() {
        _isIngested = true;
        _isVisualizing = false;
        _currentInternalPath = filePath;
        _status = "Verrouillé (mlock) dans aegis-core";
      });
    } else {
      setState(() => _status = "Erreur FFI Ingest : Code $res");
    }
  }

  void _purge() {
    if (_nativePurge != null) _nativePurge!();
    setState(() {
      _isIngested = false;
      _isVisualizing = false;
      _currentInternalPath = null;
      _status = "TAMPON PURGÉ (Zeroize)";
    });
  }

  @override
  Widget build(BuildContext context) {
    const brandYellow = Color(0xFFFCBE0B);
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("Vault Interne (Zéro Trace)", style: TextStyle(fontSize: 14)),
        backgroundColor: Colors.grey[900],
        iconTheme: const IconThemeData(color: Colors.white),
        actions: [
          if (_isIngested) 
            IconButton(icon: const Icon(Icons.delete_forever, color: Colors.red), onPressed: _purge)
        ],
      ),
      body: Column(
        children: [
          // Écran de projection VRAM
          Expanded(
            flex: 2,
            child: Container(
              margin: const EdgeInsets.all(8.0),
              decoration: BoxDecoration(border: Border.all(color: _isIngested ? brandYellow : Colors.grey[800]!)),
              child: _isVisualizing && _currentInternalPath != null
                  ? AndroidView(
                      viewType: 'com.aegis.p2p/blind_surface',
                      creationParams: {'filePath': _currentInternalPath},
                      creationParamsCodec: const StandardMessageCodec(),
                    )
                  : Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.shield, size: 60, color: _isIngested ? brandYellow : Colors.white38),
                          const SizedBox(height: 12),
                          Text(
                            _isIngested ? "Fichier isolé en RAM native" : "Aucun fichier en mémoire",
                            style: const TextStyle(color: Colors.white),
                          ),
                        ],
                      ),
                    ),
            ),
          ),
          
          // Barre de statut
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8.0),
            child: Text(_status, style: const TextStyle(color: Colors.white70, fontSize: 11), textAlign: TextAlign.center),
          ),
          
          // Contrôles BRAVO (Capture, Nettoyage, Affichage, Envoi)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12.0),
            child: Wrap(
              alignment: WrapAlignment.center,
              spacing: 10.0,
              runSpacing: 10.0,
              children: [
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.redAccent, foregroundColor: Colors.white),
                  onPressed: _triggerHardwareCapture,
                  icon: const Icon(Icons.camera),
                  label: const Text("CAPTURE NDK", style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                ),
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                  onPressed: _isIngested ? _applyPrnuAndSave : null,
                  icon: const Icon(Icons.cleaning_services),
                  label: const Text("DÉPURER & SCELLER (.aegis)", style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                ),
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.greenAccent, foregroundColor: Colors.black),
                  // Bloque l'affichage si le fichier n'a pas encore été scellé (path nul)
                  onPressed: (_isIngested && _currentInternalPath != null && !_isVisualizing) 
                      ? () => setState(() => _isVisualizing = true) 
                      : null,
                  icon: const Icon(Icons.remove_red_eye),
                  label: const Text("AFFICHER (VRAM)", style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                ),
                ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, foregroundColor: Colors.white),
                  // Bloque l'envoi P2P si le fichier n'a pas encore été scellé
                  onPressed: (_isIngested && _currentInternalPath != null) ? _sendOverTor : null,
                  icon: const Icon(Icons.cell_tower),
                  label: const Text("ENVOYER P2P (TOR)", style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),

          // Liste des conteneurs locaux (Sandbox interne)
          Expanded(
            flex: 1,
            child: ListView.builder(
              itemCount: _sandboxFiles.length,
              itemBuilder: (context, index) {
                final file = _sandboxFiles[index];
                final fileName = file.path.split('/').last;
                return ListTile(
                  leading: const Icon(Icons.lock, color: brandYellow),
                  title: Text(fileName, style: const TextStyle(color: Colors.white70, fontSize: 12)),
                  trailing: IconButton(
                    icon: const Icon(Icons.download, color: Colors.greenAccent),
                    onPressed: () {
                      _ingestPath(file.path);
                    },
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}