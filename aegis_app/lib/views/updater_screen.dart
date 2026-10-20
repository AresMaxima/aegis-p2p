// aegis_app/lib/views/updater_screen.dart
//
// P0-A.8c.3 (2026-10-20) — UI de l'updater in-app (P-6).
//
// Décisions actées (Q29-Q31) :
//   Q29 — Bannière réutilisable + dialogue complet.
//   Q30 — JAMAIS de blocage, même en force_update = true.
//         "Plus tard" toujours cliquable (hors réseau → l'utilisateur
//         doit pouvoir continuer, en va potentiellement de sa vie).
//   Q31 — Dialogue modal avec LinearProgressIndicator + pourcentage + MB.
//
// Sécurité (C86) :
//   - Aucune URL / hash / signature affichés.
//   - Changelog = texte signé (déjà validé côté Rust : pas de <>, max 500).
//   - Erreurs = messages génériques (pas de détail technique).

import 'dart:async';
import 'package:flutter/material.dart';

import '../services/updater_service.dart';
import '../updater_bridge.dart';

// =========================================================================
// Bannière réutilisable
// =========================================================================

/// Bandeau "Mise à jour disponible" à placer en haut de la navigation
/// principale (ex. sous l'AppBar de main.dart).
///
/// Auto-masquée si l'état n'est pas `available`.
/// Couleur : bleu (suggestion) / rouge (force_update).
class UpdaterBanner extends StatelessWidget {
  final UpdaterService service;

  const UpdaterBanner({super.key, required this.service});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: service,
      builder: (context, _) {
        if (service.state != UpdaterState.available) {
          return const SizedBox.shrink();
        }
        final m = service.manifest;
        if (m == null) return const SizedBox.shrink();

        final isForce = m.forceUpdate;
        final bg = isForce
            ? const Color(0xFFB00020) // rouge Material alert
            : const Color(0xFF1565C0); // bleu Material info
        final fg = Colors.white;

        return Material(
          color: bg,
          child: InkWell(
            onTap: () => showUpdaterDialog(context, service),
            child: Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: 16, vertical: 12,
              ),
              child: Row(
                children: [
                  Icon(
                    isForce
                        ? Icons.security_rounded
                        : Icons.download_rounded,
                    color: fg,
                    size: 20,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          isForce
                              ? 'Mise à jour de sécurité critique'
                              : 'Mise à jour disponible',
                          style: TextStyle(
                            color: fg,
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                        Text(
                          'Version ${m.version}',
                          style: TextStyle(
                            color: fg.withValues(alpha: 0.85),
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Icon(Icons.chevron_right_rounded, color: fg, size: 20),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

// =========================================================================
// Dialogue modal
// =========================================================================

/// Affiche le dialogue de mise à jour.
///
/// États :
///   available     → changelog + boutons [Plus tard] [Mettre à jour]
///   downloading   → LinearProgressIndicator + X MB / Y MB (Z%)
///   installing    → "Installation lancée…" (peut être fermé)
///   error         → message + [Plus tard] [Réessayer]
Future<void> showUpdaterDialog(
  BuildContext context,
  UpdaterService service,
) {
  return showDialog<void>(
    context: context,
    barrierDismissible: false, // on veut l'action explicite
    builder: (ctx) => _UpdaterDialog(service: service),
  );
}

class _UpdaterDialog extends StatefulWidget {
  final UpdaterService service;

  const _UpdaterDialog({required this.service});

  @override
  State<_UpdaterDialog> createState() => _UpdaterDialogState();
}

class _UpdaterDialogState extends State<_UpdaterDialog> {
  StreamSubscription<UpdateProgress>? _progressSub;

  @override
  void initState() {
    super.initState();
    widget.service.addListener(_onServiceChanged);
  }

  @override
  void dispose() {
    widget.service.removeListener(_onServiceChanged);
    _progressSub?.cancel();
    super.dispose();
  }

  void _onServiceChanged() {
    if (mounted) setState(() {});
    // Si l'install est terminée (state = installing), on ferme le dialogue.
    if (widget.service.state == UpdaterState.installing) {
      Navigator.of(context).maybePop();
    }
  }

  @override
  Widget build(BuildContext context) {
    final m = widget.service.manifest;
    final state = widget.service.state;

    return AlertDialog(
      title: Row(
        children: [
          Icon(
            (m?.forceUpdate ?? false)
                ? Icons.security_rounded
                : Icons.system_update_rounded,
            color: (m?.forceUpdate ?? false)
                ? const Color(0xFFB00020)
                : Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              state == UpdaterState.downloading
                  ? 'Téléchargement…'
                  : 'Mise à jour disponible',
            ),
          ),
        ],
      ),
      content: SingleChildScrollView(
        child: _buildBody(context, m, state),
      ),
      actions: _buildActions(context, m, state),
    );
  }

  Widget _buildBody(
    BuildContext context,
    dynamic m,
    UpdaterState state,
  ) {
    if (m == null) {
      return const Text('Aucune mise à jour.');
    }

    if (state == UpdaterState.downloading) {
      return _buildProgress(context);
    }

    if (state == UpdaterState.error) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            widget.service.errorMessage ?? 'Erreur inconnue.',
            style: const TextStyle(color: Color(0xFFB00020)),
          ),
          const SizedBox(height: 8),
          Text(
            'Vous pouvez continuer à utiliser AEGIS. '
            'Réessayez plus tard si vous le souhaitez.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      );
    }

    final isForce = m.forceUpdate as bool;
    final changelog = (m.changelog as String).trim();

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Version ${m.version as String}'),
        if (changelog.isNotEmpty) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              changelog,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ),
        ],
        if (isForce) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFFB00020).withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: const Color(0xFFB00020).withValues(alpha: 0.4),
              ),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.warning_amber_rounded,
                  color: Color(0xFFB00020),
                  size: 20,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Mise à jour fortement recommandée (sécurité).',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: const Color(0xFFB00020),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildProgress(BuildContext context) {
    final p = widget.service.progress;
    final downloaded = p?.downloaded ?? 0;
    final total = p?.total ?? 0;
    final fraction = p?.fraction ?? 0.0;
    final percent = (fraction * 100).toStringAsFixed(1);
    final dlMb = (downloaded / (1024 * 1024)).toStringAsFixed(1);
    final totalMb = total > 0
        ? (total / (1024 * 1024)).toStringAsFixed(1)
        : '?';

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        LinearProgressIndicator(value: total > 0 ? fraction : null),
        const SizedBox(height: 12),
        Text(
          total > 0
              ? '$dlMb Mo / $totalMb Mo  ($percent %)'
              : '$dlMb Mo téléchargés…',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }

  List<Widget> _buildActions(
    BuildContext context,
    dynamic m,
    UpdaterState state,
  ) {
    // En cours de download → pas d'action, on attend.
    if (state == UpdaterState.downloading) {
      return const [];
    }

    // Erreur → [Plus tard] [Réessayer]
    if (state == UpdaterState.error) {
      return [
        TextButton(
          onPressed: () => Navigator.of(context).maybePop(),
          child: const Text('Plus tard'),
        ),
        FilledButton(
          onPressed: () => widget.service.install(),
          child: const Text('Réessayer'),
        ),
      ];
    }

    // Idle / available → [Plus tard] [Mettre à jour]
    // Q30 : "Plus tard" TOUJOURS actif, même en force_update.
    return [
      TextButton(
        onPressed: () {
          widget.service.dismissUpdate();
          Navigator.of(context).maybePop();
        },
        child: const Text('Plus tard'),
      ),
      FilledButton.icon(
        icon: const Icon(Icons.download_rounded),
        label: const Text('Mettre à jour'),
        onPressed: () async {
          final allowed = await widget.service.ensureInstallAllowed();
          if (!allowed) {
            // L'utilisateur a été redirigé vers les paramètres Android.
            // Le dialogue reste ouvert, l'utilisateur relancera.
            return;
          }
          await widget.service.install();
        },
      ),
    ];
  }
}