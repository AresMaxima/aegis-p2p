import 'dart:math';
import 'package:flutter/material.dart';
import '../main.dart';                    // drownKeyFfi, extractKeyFfi
import '../services/global_state.dart';   // globalSteganoRamBuffer
import '../translations.dart';

class SteganographyView extends StatefulWidget {
  const SteganographyView({super.key});

  @override
  State<SteganographyView> createState() => _SteganographyViewState();
}

class _SteganographyViewState extends State<SteganographyView> {
  final TextEditingController _steganoController = TextEditingController();
  String _steganoResult = "";

  // Q1 FIX (2026-09-23) : suppression du _localizedPoems local (fr+en seulement).
  // Désormais : AppTranslations.getPoems(context) → 7 langues avec fallback.

  @override
  void dispose() {
    _steganoController.dispose();
    super.dispose();
  }

  void _drownKeyInPoem() {
    final text = _steganoController.text.trim();
    if (text.isEmpty) return;

    // Q1 FIX (2026-09-23) : utilise les 7 langues depuis AppTranslations.
    final poemsList = AppTranslations.getPoems(context);
    final poem = poemsList[Random().nextInt(poemsList.length)];

    setState(() {
      _steganoResult = drownKeyFfi(text, poem);
      _steganoController.clear();
    });
  }

  void _extractKeyFromPoem() {
    final text = _steganoController.text.trim();
    if (text.isEmpty) return;

    setState(() {
      _steganoResult = extractKeyFfi(text);
      _steganoController.clear();
    });
  }

  void _sendStegoOverTor(String poem) {
    debugPrint("Expédition P2P : $poem");
  }

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(AppTranslations.get(context, 'stegano_title'),
                style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow)),
            ElevatedButton.icon(
              onPressed: () {
                if (globalSteganoRamBuffer.isNotEmpty) {
                  setState(() {
                    _steganoController.text = globalSteganoRamBuffer;
                  });
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(AppTranslations.get(context, 'toast_ram_restored')),
                      backgroundColor: Colors.green,
                    ),
                  );
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(AppTranslations.get(context, 'toast_ram_empty')),
                      backgroundColor: Colors.red,
                    ),
                  );
                }
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.grey[800],
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 12),
              ),
              icon: const Icon(Icons.download, size: 16),
              label: Text(AppTranslations.get(context, 'btn_restore'),
                  style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
            ),
          ],
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _steganoController,
          maxLines: 3,
          enableInteractiveSelection: false,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: AppTranslations.get(context, 'stegano_hint_field'),
            hintStyle: const TextStyle(color: Colors.white38),
            filled: true,
            fillColor: Colors.grey[900],
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8.0)),
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: ElevatedButton(
                onPressed: _drownKeyInPoem,
                style: ElevatedButton.styleFrom(
                  backgroundColor: brandYellow,
                  foregroundColor: Colors.black,
                ),
                child: Text(AppTranslations.get(context, 'stegano_btn'),
                    style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: ElevatedButton(
                onPressed: _extractKeyFromPoem,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.blueGrey,
                  foregroundColor: Colors.white,
                ),
                child: Text(AppTranslations.get(context, 'stegano_extract_btn'),
                    style: const TextStyle(fontSize: 10)),
              ),
            ),
          ],
        ),
        if (_steganoResult.isNotEmpty) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(16.0),
            decoration: BoxDecoration(
              color: Colors.black87,
              border: Border.all(color: brandYellow),
              borderRadius: BorderRadius.circular(8.0),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  AppTranslations.get(context, 'stegano_container_title'),
                  style: const TextStyle(
                      color: brandYellow,
                      fontSize: 12,
                      fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                // Q2 FIX v2.2 (2026-09-24) : retrait fontStyle.italic + height:1.5.
                // Test : sur Exynos 990 + Skia, le faux-italique appliqué à un
                // text run contenant 800+ caractères Cf (invisibles) provoque
                // une micro-avance cumulative par caractère → mots visibles
                // anormalement éloignés.
                Text(
                  _steganoResult,
                  style: const TextStyle(
                      color: Colors.white70),
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      flex: 2,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.blueAccent,
                          foregroundColor: Colors.white,
                        ),
                        icon: const Icon(Icons.cell_tower),
                        label: Text(AppTranslations.get(context, 'btn_send_tor'),
                            style: const TextStyle(
                                fontWeight: FontWeight.bold, fontSize: 11)),
                        onPressed: () => _sendStegoOverTor(_steganoResult),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      flex: 1,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.grey[800],
                          foregroundColor: Colors.white,
                        ),
                        icon: const Icon(Icons.memory),
                        label: Text(AppTranslations.get(context, 'btn_save_ram'),
                            style: const TextStyle(
                                fontWeight: FontWeight.bold, fontSize: 11)),
                        onPressed: () {
                          globalSteganoRamBuffer = _steganoResult;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text(AppTranslations.get(context, 'toast_poem_in_ram')),
                              backgroundColor: Colors.green,
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}