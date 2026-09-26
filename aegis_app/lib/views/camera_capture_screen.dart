import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../translations.dart';

/// Écran plein de capture caméra avec aperçu LIVE.
///
/// Retourne :
///   true  → l'utilisateur a tapé CAPTURER (frames YUV en RAM Rust)
///   false → l'utilisateur a annulé
class CameraCaptureScreen extends StatefulWidget {
  const CameraCaptureScreen({super.key});

  @override
  State<CameraCaptureScreen> createState() => _CameraCaptureScreenState();
}

class _CameraCaptureScreenState extends State<CameraCaptureScreen> {
  static const MethodChannel _channel = MethodChannel('com.aegis.p2p/camera');

  bool _isCapturing = false;
  String? _errorMessage;

  final Color _steel     = const Color(0xFF8D99AE);
  final Color _matteGold = const Color(0xFFD4AF37);
  final TextStyle _industrialText = const TextStyle(
    fontFamily: 'RobotoMono',
    letterSpacing: 1.5,
    fontWeight: FontWeight.w600,
    fontSize: 12,
  );

  @override
  void initState() {
    super.initState();
    _startCamera();
  }

  Future<void> _startCamera() async {
    try {
      final res = await _channel.invokeMethod<int>('startNativeCamera');
      if (res != 0) {
        setState(() => _errorMessage =
            "${AppTranslations.get(context, 'cam_err_start')} (code=$res)");
      }
    } on PlatformException catch (e) {
      setState(() => _errorMessage =
          "${AppTranslations.get(context, 'cam_err_permission')} : ${e.message}");
    } catch (e) {
      setState(() => _errorMessage =
          "${AppTranslations.get(context, 'cam_err_generic')} : $e");
    }
  }

  Future<void> _onCapture() async {
    if (_isCapturing) return;
    setState(() {
      _isCapturing = true;
      _errorMessage = null;
    });

    try {
      await _channel.invokeMethod<int>('stopNativeCamera');
      if (!mounted) return;
      Navigator.pop(context, true);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isCapturing = false;
        _errorMessage =
            "${AppTranslations.get(context, 'cam_err_stop')} : $e";
      });
    }
  }

  Future<void> _onCancel() async {
    try {
      await _channel.invokeMethod<int>('stopNativeCamera');
    } catch (_) {}
    if (!mounted) return;
    Navigator.pop(context, false);
  }

  @override
  void dispose() {
    // Filet de sécurité : arrête la caméra si l'écran est démonté autrement.
    _channel.invokeMethod<int>('stopNativeCamera').catchError((_) => -1);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Stack(
          children: [
            // APERÇU LIVE (CameraX Preview → SurfaceView)
            Positioned.fill(
              child: AndroidView(
                viewType: 'com.aegis.p2p/camera_preview',
                creationParamsCodec: const StandardMessageCodec(),
              ),
            ),

            // BOUTON ANNULER (en haut à gauche)
            Positioned(
              top: 12,
              left: 12,
              child: OutlinedButton.icon(
                onPressed: _isCapturing ? null : _onCancel,
                style: OutlinedButton.styleFrom(
                  side: BorderSide(color: _steel, width: 1.5),
                  backgroundColor: Colors.black54,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                ),
                icon: const Icon(Icons.close, size: 16),
                label: Text(AppTranslations.get(context, 'cam_btn_cancel'),
                    style: _industrialText),
              ),
            ),

            // MESSAGE D'ERREUR (bandeau)
            if (_errorMessage != null)
              Positioned(
                top: 12,
                left: 130,
                right: 12,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  color: Colors.redAccent.withValues(alpha: 0.85),
                  child: Text(
                    _errorMessage!,
                    style: _industrialText.copyWith(color: Colors.white, fontSize: 10),
                    textAlign: TextAlign.center,
                  ),
                ),
              ),

            // BOUTON CAPTURER (bas centré, gros et évident)
            Positioned(
              bottom: 32,
              left: 0,
              right: 0,
              child: Center(
                child: GestureDetector(
                  onTap: _isCapturing ? null : _onCapture,
                  child: Container(
                    width: 84,
                    height: 84,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: _isCapturing ? _steel : _matteGold,
                      border: Border.all(color: Colors.white, width: 4),
                      boxShadow: [
                        BoxShadow(
                          color: _matteGold.withValues(alpha: 0.5),
                          blurRadius: 20,
                          spreadRadius: 4,
                        ),
                      ],
                    ),
                    child: _isCapturing
                        ? const Padding(
                            padding: EdgeInsets.all(24),
                            child: CircularProgressIndicator(
                              strokeWidth: 3,
                              color: Colors.white,
                            ),
                          )
                        : const Icon(
                            Icons.camera_alt_sharp,
                            size: 42,
                            color: Colors.black,
                          ),
                  ),
                ),
              ),
            ),

            // INDICATEUR "CAPTURE RAM" (top-right)
            Positioned(
              top: 12,
              right: 12,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  border: Border.all(color: _matteGold, width: 1),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: const BoxDecoration(
                        shape: BoxShape.circle,
                        color: Colors.redAccent,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      AppTranslations.get(context, 'cam_indicator_ram'),
                      style: _industrialText.copyWith(
                        color: _matteGold,
                        fontSize: 9,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}