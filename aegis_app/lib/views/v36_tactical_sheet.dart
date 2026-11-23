import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../services/global_state.dart';
import '../v36_hardening_bridge.dart';

class V36TacticalSheet extends StatefulWidget {
  final ValueChanged<String>? onMessageReceived;
  const V36TacticalSheet({super.key, this.onMessageReceived});
  @override
  State<V36TacticalSheet> createState() => _V36TacticalSheetState();
}

class _V36TacticalSheetState extends State<V36TacticalSheet> {
  static const Color _gold = Color(0xFFFCBE0B);
  static const Color _card = Color(0xFF17171B);
  String _statusBanner = 'Boucliers v3.6 prets (100% RAM volatile - Zero SQLite)';

  Future<void> _runSelfAttestationTest() async {
    final pk = V36HardeningBridge.getOwnEd25519PublicKey() ?? Uint8List(32);
    final rng = Random.secure();
    final nonce = Uint8List.fromList(List<int>.generate(32, (_) => rng.nextInt(256)));
    setState(() => _statusBanner = 'C91 : Interrogation StrongBox / Titan M2 / Knox...');
    final der = await V36HardeningBridge.generateOwnPeerAttestation(pk, nonce);
    if (!mounted) return;
    if (der == null) {
      setState(() => _statusBanner = 'C91 : Chaine X.509 indisponible sur ce terminal.');
      return;
    }
    final rc = V36HardeningBridge.verifyPeerAttestation(
      derChain: der, peerEd25519Pk32: pk, sessionNonce32: nonce,
    );
    setState(() => _statusBanner = rc == 0
        ? 'C91 VALIDE : X.509 (${der.length} B DER) verifie par Rust !'
        : 'C91 Code retour Rust : $rc (${der.length} B DER)');
  }

  void _checkRamDeadDrops() {
    final pk = V36HardeningBridge.getOwnEd25519PublicKey();
    if (pk == null) {
      setState(() => _statusBanner = 'C93 : Deverrouillez le coffre pour deriver le tag.');
      return;
    }
    final drops = V36HardeningBridge.collectOwnDeadDrops(pk);
    if (drops.isEmpty) {
      setState(() => _statusBanner = 'C93 : 0 enveloppe Dead-Drop sur cette heure UTC.');
      return;
    }
    for (final d in drops) {
      final dec = utf8.decode(d, allowMalformed: true);
      widget.onMessageReceived?.call('[DEAD-DROP RAM]: $dec');
    }
    setState(() => _statusBanner = 'C93 : ${drops.length} enveloppe(s) extraite(s) & purgees !');
  }

  Future<void> _enrollNfc() async {
    beginExternalFlow();
    setState(() => _statusBanner = 'C94 : Approchez votre YubiKey 5 NFC au dos...');
    try {
      final ok = await V36HardeningBridge.enrollExternalNfcToken();
      if (!mounted) return;
      setState(() => _statusBanner = ok
          ? 'C94 ACTIF : Identite Ed25519 scellee par jeton NFC !'
          : 'C94 : Lecture NFC annulee ou desactivee.');
    } finally {
      endExternalFlow();
    }
  }
  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text('BOUCLIERS ANTI-SIGINT & AIR-GAP v3.6', style: TextStyle(color: _gold, fontWeight: FontWeight.bold, fontSize: 15)),
                  IconButton(icon: const Icon(Icons.close, color: Colors.white70), onPressed: () => Navigator.pop(context)),
                ],
              ),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(6), border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4))),
                child: Text(_statusBanner, style: const TextStyle(color: Colors.greenAccent, fontSize: 12)),
              ),
              Container(
                decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8)),
                child: ValueListenableBuilder<bool>(
                  valueListenable: V36HardeningBridge.chaffActive,
                  builder: (_, active, __) => SwitchListTile(
                    activeColor: _gold,
                    title: const Text('C90 - Trafic Factice Constant (512 B)', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                    subtitle: ValueListenableBuilder<int>(
                      valueListenable: V36HardeningBridge.chaffCellsEmitted,
                      builder: (_, c, __) => Text('Anti-correlation SIGINT - Cellules : $c', style: const TextStyle(fontSize: 11, color: Colors.white60)),
                    ),
                    value: active,
                    onChanged: (v) {
                      V36HardeningBridge.configureChaffing(enabled: v, intervalMs: 1000);
                      setState(() => _statusBanner = v ? 'C90 ACTIF : Flux constant 512 B/s engage.' : 'C90 : Flux factice suspendu.');
                    },
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Container(
                decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8)),
                child: ListTile(
                  leading: const Icon(Icons.verified_user, color: _gold),
                  title: const Text('C91 - Attestation Materielle Mutuelle P2P', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                  subtitle: const Text('X.509 Titan M2 / Knox (VerifiedBoot GREEN)', style: TextStyle(fontSize: 11, color: Colors.white60)),
                  trailing: OutlinedButton(onPressed: _runSelfAttestationTest, child: const Text('Tester', style: TextStyle(color: _gold, fontSize: 12))),
                ),
              ),
              const SizedBox(height: 8),
              Container(
                decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8)),
                child: ListTile(
                  leading: const Icon(Icons.qr_code_2, color: Colors.greenAccent),
                  title: const Text('C92 - Pont Optique Air-Gap 0-RF (15 fps)', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                  subtitle: const Text('Luby Transform Fountain QR en Mode Avion strict', style: TextStyle(fontSize: 11, color: Colors.white60)),
                  trailing: ElevatedButton(
                    style: ElevatedButton.styleFrom(backgroundColor: _gold, foregroundColor: Colors.black),
                    onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => OpticalAirGapScreen(onDecodedText: widget.onMessageReceived))),
                    child: const Text('Ouvrir', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Container(
                decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8)),
                child: ListTile(
                  leading: const Icon(Icons.memory, color: Colors.cyanAccent),
                  title: const Text('C93 - Enveloppes Aveugles Dead-Drop RAM', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                  subtitle: const Text('Collecte Read-Once & Burn sur tag HKDF-SHA256', style: TextStyle(fontSize: 11, color: Colors.white60)),
                  trailing: OutlinedButton(onPressed: _checkRamDeadDrops, child: const Text('Collecter', style: TextStyle(color: Colors.cyanAccent, fontSize: 12))),
                ),
              ),
              const SizedBox(height: 8),
              Container(
                decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8)),
                child: ValueListenableBuilder<bool>(
                  valueListenable: V36HardeningBridge.nfcTokenSealed,
                  builder: (_, sealed, __) => ListTile(
                    leading: Icon(Icons.nfc, color: sealed ? Colors.greenAccent : _gold),
                    title: const Text('C94 - Jeton Anti-Usurpation NFC (YubiKey 5)', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                    subtitle: Text(sealed ? 'Jeton actif dans HKDF-SHA256' : 'Lie Ed25519 a un jeton physique separe', style: const TextStyle(fontSize: 11, color: Colors.white60)),
                    trailing: OutlinedButton(
                      onPressed: sealed ? V36HardeningBridge.clearExternalNfcToken : _enrollNfc,
                      child: Text(sealed ? 'Retirer' : 'Sceller', style: TextStyle(color: sealed ? Colors.redAccent : _gold, fontSize: 12)),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class OpticalAirGapScreen extends StatefulWidget {
  final ValueChanged<String>? onDecodedText;
  const OpticalAirGapScreen({super.key, this.onDecodedText});
  @override
  State<OpticalAirGapScreen> createState() => _OpticalAirGapScreenState();
}

class _OpticalAirGapScreenState extends State<OpticalAirGapScreen> {
  final TextEditingController _msgCtrl = TextEditingController();
  List<String> _frames = const [];
  int _frameIdx = 0;
  Timer? _fpsTimer;
  bool _rxMode = false;
  int _ingested = 0;
  String? _recovered;

  @override
  void dispose() {
    _fpsTimer?.cancel();
    _msgCtrl.dispose();
    super.dispose();
  }

  void _startBroadcast() {
    final t = _msgCtrl.text.trim();
    if (t.isEmpty) return;
    final f = V36HardeningBridge.encodeOpticalFountainFrames(Uint8List.fromList(utf8.encode(t)));
    if (f.isEmpty) return;
    _fpsTimer?.cancel();
    setState(() { _frames = f; _frameIdx = 0; });
    _fpsTimer = Timer.periodic(const Duration(milliseconds: 67), (_) {
      if (mounted && _frames.isNotEmpty) setState(() => _frameIdx = (_frameIdx + 1) % _frames.length);
    });
  }

  @override
  Widget build(BuildContext context) {
    const gold = Color(0xFFFCBE0B);
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        title: const Text('C92 - PONT OPTIQUE 0-RF (15 FPS)', style: TextStyle(color: gold, fontSize: 15)),
        actions: [
          TextButton.icon(
            onPressed: () => setState(() { _rxMode = !_rxMode; _fpsTimer?.cancel(); }),
            icon: Icon(_rxMode ? Icons.qr_code : Icons.camera_alt, color: Colors.greenAccent),
            label: Text(_rxMode ? 'EMETTRE' : 'SCANNER', style: const TextStyle(color: Colors.greenAccent)),
          ),
        ],
      ),
      body: Padding(padding: const EdgeInsets.all(16), child: _rxMode ? _buildRx() : _buildTx()),
    );
  }

  Widget _buildTx() {
    const gold = Color(0xFFFCBE0B);
    return Column(
      children: [
        TextField(controller: _msgCtrl, enableInteractiveSelection: false, decoration: const InputDecoration(hintText: 'Charge utile Air-Gap (Mode Avion)...', filled: true, fillColor: Color(0xFF17171B))),
        const SizedBox(height: 12),
        ElevatedButton.icon(
          style: ElevatedButton.styleFrom(backgroundColor: gold, foregroundColor: Colors.black, minimumSize: const Size(double.infinity, 46)),
          onPressed: _startBroadcast,
          icon: const Icon(Icons.play_arrow),
          label: const Text('DIFFUSER FLUX FOUNTAIN QR (15 FPS)', style: TextStyle(fontWeight: FontWeight.bold)),
        ),
        const SizedBox(height: 20),
        if (_frames.isNotEmpty)
          Expanded(
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(padding: const EdgeInsets.all(14), color: Colors.white, child: QrImageView(data: _frames[_frameIdx], version: QrVersions.auto, size: 240)),
                  const SizedBox(height: 10),
                  Text('Goutte Luby #${_frameIdx + 1} / ${_frames.length} (0 RF)', style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace')),
                ],
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildRx() {
    return Column(
      children: [
        Text(_recovered != null ? 'RECONSTRUIT EN RAM (PURGE AUTO) :' : 'Scannez le flux QR 15 fps (Gouttes : $_ingested)', style: const TextStyle(color: Colors.greenAccent, fontSize: 12)),
        const SizedBox(height: 12),
        if (_recovered != null)
          Container(width: double.infinity, padding: const EdgeInsets.all(14), decoration: BoxDecoration(color: const Color(0xFF17171B), borderRadius: BorderRadius.circular(8)), child: SelectableText(_recovered!, style: const TextStyle(color: Colors.white, fontSize: 14)))
        else
          Expanded(
            child: MobileScanner(
              onDetect: (cap) {
                for (final b in cap.barcodes) {
                  final raw = b.rawValue;
                  if (raw == null || raw.isEmpty) continue;
                  final res = V36HardeningBridge.ingestOpticalDroplet(raw);
                  if (res.status == 0) {
                    setState(() => _ingested++);
                  } else if (res.status == 1 && res.data != null) {
                    final dec = utf8.decode(res.data!, allowMalformed: true);
                    widget.onDecodedText?.call('[AIR-GAP 0-RF]: $dec');
                    setState(() => _recovered = dec);
                    break;
                  }
                }
              },
            ),
          ),
      ],
    );
  }
}
