import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../main.dart'; // Import pour les appels FFI et AppTranslations

class SteganographyView extends StatefulWidget {
  const SteganographyView({super.key});

  @override
  State<SteganographyView> createState() => _SteganographyViewState();
}

class _SteganographyViewState extends State<SteganographyView> {
  final TextEditingController _steganoController = TextEditingController();
  String _steganoResult = "";

  final Map<String, List<String>> _localizedPoems = {
    'fr': [
      "Dans l'ombre des cités silencieuses le vent murmure des secrets oubliés...",
      "Les étoiles lointaines brillent d'un éclat froid au-dessus de l'océan obscur...",
      "Sous la pluie fine de novembre les feuilles d'or recouvrent les chemins abandonnés...",
    ],
    'en': [
      "In the shadow of silent cities the wind whispers forgotten secrets...",
      "Distant stars shine with a cold light above the dark ocean...",
      "Under the fine November rain golden leaves cover the abandoned paths...",
    ],
    // Vous pouvez réintégrer les autres langues ici (es, it, pl, uk, ar)
  };

  @override
  void dispose() {
    _steganoController.dispose();
    super.dispose();
  }

  void _drownKeyInPoem() {
    final text = _steganoController.text.trim();
    if (text.isEmpty) return;

    final String langCode = Localizations.localeOf(context).languageCode;
    final poemsList = _localizedPoems[langCode] ?? _localizedPoems['en']!;
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
    // Connexion FFI vers aegis_send_p2p_tor
    debugPrint("Expédition P2P : $poem");
  }

  @override
  Widget build(BuildContext context) {
    const Color brandYellow = Color(0xFFFCBE0B);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(AppTranslations.get(context, 'stegano_title'), style: const TextStyle(fontWeight: FontWeight.bold, color: brandYellow)),
        const SizedBox(height: 8),
        TextField(
          controller: _steganoController,
          maxLines: 3,
          enableInteractiveSelection: false, // Bypass OS Clipboard
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: "Rédigez le message secret à dissimuler...",
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
                style: ElevatedButton.styleFrom(backgroundColor: brandYellow, foregroundColor: Colors.black),
                child: Text(AppTranslations.get(context, 'stegano_btn'), style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: ElevatedButton(
                onPressed: _extractKeyFromPoem,
                style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey, foregroundColor: Colors.white),
                child: Text(AppTranslations.get(context, 'stegano_extract_btn'), style: const TextStyle(fontSize: 10)),
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
                const Text(
                  "Conteneur Stéganographique (Prêt pour expédition)", 
                  style: TextStyle(color: brandYellow, fontSize: 12, fontWeight: FontWeight.bold)
                ),
                const SizedBox(height: 12),
                Text(
                  _steganoResult, 
                  style: const TextStyle(color: Colors.white70, fontStyle: FontStyle.italic, height: 1.5)
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      flex: 2,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent, foregroundColor: Colors.white),
                        icon: const Icon(Icons.cell_tower),
                        label: const Text("ENVOYER P2P (TOR)", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                        onPressed: () => _sendStegoOverTor(_steganoResult),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      flex: 1,
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(backgroundColor: Colors.grey[800], foregroundColor: Colors.white),
                        icon: const Icon(Icons.copy),
                        label: const Text("COPIER", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 11)),
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: _steganoResult));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text("Poème copié (Réseau hors-ligne)"), backgroundColor: Colors.grey),
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