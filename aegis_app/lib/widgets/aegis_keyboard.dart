import 'dart:math';
import 'package:flutter/material.dart';

/// Clavier AEGIS custom — saisie sécurisée du PIN sans IME système.
///
/// Objectifs sécurité :
///   • Évite le clavier système (Samsung Keyboard, Gboard) qui loggue
///     les frappes et les envoie en telemetry.
///   • Layout randomisé à chaque appel pour résister à l'épaule-surfing.
///   • Aucune suggestion / autocomplete / autocorrect.
///   • Bouton coller désactivé — le PIN ne vient jamais du presse-papier.
class AegisKeyboard extends StatefulWidget {
  final TextEditingController controller;
  final VoidCallback? onInput;
  final bool obscureText;
  final Color brandYellow;

  const AegisKeyboard({
    super.key,
    required this.controller,
    this.onInput,
    this.obscureText = true,
    this.brandYellow = const Color(0xFFFCBE0B),
  });

  @override
  State<AegisKeyboard> createState() => _AegisKeyboardState();
}

class _AegisKeyboardState extends State<AegisKeyboard> {
  static const List<String> _row1 = ['q','w','e','r','t','y','u','i','o','p'];
  static const List<String> _row2 = ['a','s','d','f','g','h','j','k','l'];
  static const List<String> _row3 = ['z','x','c','v','b','n','m'];
  static const List<String> _row4num = ['1','2','3','4','5','6','7','8','9','0'];
  static const List<String> _row4sym = ['.','-','_','@','#','!','?','&','*','+'];

  late List<String> _r1, _r2, _r3, _r4;
  bool _showSymbols = false;
  bool _showPassword = false;
  bool _capsLock = false;

  @override
  void initState() {
    super.initState();
    _shuffleLayout();
  }

  void _shuffleLayout() {
    final rng = Random.secure();
    _r1 = List.of(_row1)..shuffle(rng);
    _r2 = List.of(_row2)..shuffle(rng);
    _r3 = List.of(_row3)..shuffle(rng);
    _r4 = List.of(_showSymbols ? _row4sym : _row4num)..shuffle(rng);
  }

  void _onKeyTap(String char) {
    final c = _capsLock ? char.toUpperCase() : char;
    final text = widget.controller.text;
    widget.controller.text = text + c;
    widget.controller.selection = TextSelection.collapsed(
      offset: widget.controller.text.length,
    );
    widget.onInput?.call();
  }

  void _onBackspace() {
    final text = widget.controller.text;
    if (text.isEmpty) return;
    widget.controller.text = text.substring(0, text.length - 1);
    widget.controller.selection = TextSelection.collapsed(
      offset: widget.controller.text.length,
    );
    widget.onInput?.call();
  }

  void _onClear() {
    widget.controller.clear();
    widget.onInput?.call();
  }

  void _onToggleSymbols() {
    setState(() {
      _showSymbols = !_showSymbols;
      _shuffleLayout();
    });
  }

  void _onToggleCaps() {
    setState(() {
      _capsLock = !_capsLock;
    });
  }

  void _onToggleShowPassword() {
    setState(() {
      _showPassword = !_showPassword;
    });
  }

  Widget _key(
    String char, {
    double flex = 1,
    Color? bgColor,
    Color? fgColor,
    VoidCallback? onTap,
    Widget? child,
  }) {
    return Expanded(
      flex: flex.toInt(),
      child: Padding(
        padding: const EdgeInsets.all(2.0),
        child: Material(
          color: bgColor ?? Colors.grey[900],
          borderRadius: BorderRadius.circular(6),
          child: InkWell(
            borderRadius: BorderRadius.circular(6),
            onTap: onTap ?? () => _onKeyTap(char),
            child: Container(
              height: 44,
              alignment: Alignment.center,
              child: child ??
                  Text(
                    _capsLock ? char.toUpperCase() : char,
                    style: TextStyle(
                      color: fgColor ?? Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _row(List<String> chars) {
    return Row(
      children: chars.map((c) => _key(c)).toList(),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
      decoration: BoxDecoration(
        color: Colors.black,
        border: Border(
          top: BorderSide(color: widget.brandYellow.withValues(alpha: 0.3)),
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    widget.obscureText && !_showPassword
                        ? '•' * widget.controller.text.length
                        : widget.controller.text,
                    style: const TextStyle(
                      color: Colors.white,
                      fontFamily: 'monospace',
                      fontSize: 14,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                IconButton(
                  icon: Icon(
                    _showPassword ? Icons.visibility_off : Icons.visibility,
                    color: Colors.grey,
                    size: 20,
                  ),
                  onPressed: _onToggleShowPassword,
                ),
              ],
            ),
          ),
          _row(_r1),
          _row(_r2),
          Row(
            children: [
              _key('⇧', flex: 1.5, bgColor: Colors.grey[800],
                  onTap: _onToggleCaps,
                  child: Icon(
                    _capsLock ? Icons.keyboard_capslock : Icons.arrow_upward,
                    color: Colors.white,
                    size: 18,
                  )),
              ..._r3.map((c) => _key(c)),
              _key('⌫', flex: 1.5, bgColor: Colors.redAccent[700],
                  onTap: _onBackspace,
                  child: const Icon(Icons.backspace_outlined,
                      color: Colors.white, size: 18)),
            ],
          ),
          _row(_r4),
          Row(
            children: [
              _key('?123', flex: 2, bgColor: Colors.grey[800],
                  onTap: _onToggleSymbols,
                  child: Text(
                    _showSymbols ? 'ABC' : '?123',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                    ),
                  )),
              _key(' ', flex: 6, bgColor: Colors.grey[800]),
              _key('CLR', flex: 2, bgColor: Colors.orange[800],
                  onTap: _onClear,
                  child: const Text(
                    'CLR',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  )),
            ],
          ),
        ],
      ),
    );
  }
}