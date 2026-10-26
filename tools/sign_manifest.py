#!/usr/bin/env python3
"""
sign_manifest.py — Signature de manifeste AEGIS (P0-A.8d.2).

RÈGLE SACRO-SAINTE :
  Cet outil DOIT être exécuté UNIQUEMENT sur la machine air-gapped
  qui contient la clé privée admin. Toute exécution sur une machine
  connectée est un risque de fuite.

Sécurité :
  - Détection réseau best-effort (C87) : refuse de tourner si connecté
  - Séparation de domaine (C89) : signe b"MANIFEST:v1:" + bytes JSON canoniques
  - Vérification de la clé publique contre ADMIN_PUBLIC_KEY_HEX (lib.rs)
  - Canonicalisation JSON : clés triées, sans espaces, UTF-8 sans BOM, LF
  - Écriture des bytes signés tel quels (pas de re-sérialisation après signature)

Usage :
  # 1. Générer un template
  python sign_manifest.py template --version 3.2.0 --out manifest.json

  # 2. Éditer manifest.json (Notepad, UTF-8 sans BOM, LF)
  #    Remplacer REPLACE_WITH_* par vraies valeurs
  #    Renseigner apk_sha256 = sha256sum de l'APK release

  # 3. Signer
  python sign_manifest.py sign --key admin.key --manifest manifest.json

  # 4. Transférer manifest.json + manifest.json.sig sur aresmaxima.com

Rotation (compromission suspectée) :
  python sign_manifest.py rotate --out new_admin.key --allow-connected

Destruction (perte/fin de vie) :
  python sign_manifest.py destroy --key admin.key --confirm
"""

import argparse
import hashlib
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 sur stdout/stderr (Windows cp1252 → erreurs unicode sinon)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

if sys.version_info < (3, 8):
    sys.exit("FATAL: Python 3.8+ requis")

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    sys.exit("FATAL: package 'cryptography' non installé. pip install cryptography")

# =============================================================================
# Constantes synchronisées avec lib.rs / updater.rs
# =============================================================================

# Doit matcher exactement ADMIN_PUBLIC_KEY_BYTES dans aegis-core/src/lib.rs
ADMIN_PUBLIC_KEY_HEX = (
    "bb45a7db9a81c9609dbc8f93ab879c2f382fc73cb3871cb103a4b653c385cd87"
)

# Doit matcher updater::MANIFEST_DOMAIN
MANIFEST_DOMAIN = b"MANIFEST:v1:"

# =============================================================================
# Helpers
# =============================================================================

def _check_network_disconnected(allow_connected: bool) -> None:
    """Best-effort : refuse de tourner si une connexion réseau est active."""
    if allow_connected:
        print("⚠️  --allow-connected : réseau non vérifié. RISQUE DE FUITE.", file=sys.stderr)
        return
    try:
        s = socket.create_connection(("1.1.1.1", 53), timeout=1)
        s.close()
        sys.exit(
            "FATAL: réseau détecté.\n"
            "Cet outil doit tourner sur une machine air-gapped.\n"
            "Déconnectez-vous, ou utilisez --allow-connected (déconseillé)."
        )
    except OSError:
        pass


def _load_privkey(path_or_hex: str) -> bytes:
    """Charge une clé privée ed25519 depuis un fichier ou une chaîne hex."""
    p = Path(path_or_hex)
    if p.exists():
        raw = p.read_text(encoding="utf-8").strip()
    else:
        raw = path_or_hex.strip()
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError:
        sys.exit(f"FATAL: clé privée non-hex ou invalide ({len(raw)} chars)")
    if len(key_bytes) != 32:
        sys.exit(f"FATAL: clé privée doit faire 32 octets, pas {len(key_bytes)}")
    return key_bytes


def _verify_pubkey_matches_admin(key_bytes: bytes) -> str:
    """Vérifie que la clé privée dérive la bonne clé publique admin."""
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    actual = priv.public_key().public_bytes_raw().hex()
    if actual != ADMIN_PUBLIC_KEY_HEX:
        sys.exit(
            f"FATAL: pubkey dérivée ne correspond pas.\n"
            f"  dérivée    : {actual}\n"
            f"  attendue   : {ADMIN_PUBLIC_KEY_HEX}\n"
            f"Vérifiez ADMIN_PUBLIC_KEY_BYTES dans aegis-core/src/lib.rs.\n"
            f"Si vous êtes en rotation : utilisez la NOUVELLE clé attendue."
        )
    return actual


def _canonicalize(obj: dict) -> bytes:
    """JSON canonique : clés triées, sans espaces, UTF-8 sans BOM."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _format_rust_pubkey(pub_hex: str) -> str:
    """Formate une pubkey hex en [u8; 32] Rust, 8 par ligne."""
    bs = [int(pub_hex[i:i + 2], 16) for i in range(0, 64, 2)]
    lines = []
    for i in range(0, 32, 8):
        row = ", ".join(f"0x{b:02x}" for b in bs[i:i + 8])
        lines.append(f"    {row},")
    return "pub const ADMIN_PUBLIC_KEY_BYTES: [u8; 32] = [\n" + "\n".join(lines) + "\n];"


# =============================================================================
# Subcommands
# =============================================================================

def cmd_template(args: argparse.Namespace) -> None:
    """Génère un template de manifeste JSON (squelette à éditer)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "app_id": "aegis",
        "version": args.version,
        "issued_at": now,
        "min_from_version": args.min_from,
        "apk_url": f"https://aresmaxima.com/update/aegis-{args.version}.apk",
        "apk_host_whitelist": ["aresmaxima.com"],
        "apk_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256_OF_APK",
        "apk_signing_cert_sha256": None,
        "force_update": False,
        "changelog": "REPLACE_WITH_CHANGELOG_NO_ANGLE_BRACKETS",
    }
    out = Path(args.out)
    pretty = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(pretty)
    print(f"Template écrit : {out} ({out.stat().st_size} bytes)")
    print()
    print("INSTRUCTIONS :")
    print("  1. Ouvrir dans Notepad (UTF-8 sans BOM)")
    print("  2. Remplacer :")
    print("     - apk_sha256          : sha256sum de l'APK release (64 hex lowercase)")
    print("     - changelog           : texte court, INTERDIT d'utiliser < ou >")
    print("     - min_from_version    : version minimale du client requise")
    print("     - force_update        : true seulement si CVE critique")
    print("  3. Signer :")
    print(f"     python sign_manifest.py sign --key admin.key --manifest {out.name}")


def cmd_sign(args: argparse.Namespace) -> None:
    """Signe un manifeste. Écrit le JSON canonique + .sig."""
    _check_network_disconnected(args.allow_connected)

    key_bytes = _load_privkey(args.key)
    _verify_pubkey_matches_admin(key_bytes)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

    manifest_path = Path(args.manifest)
    try:
        raw_bytes = manifest_path.read_bytes()
        manifest_dict = json.loads(raw_bytes.decode("utf-8"))
    except OSError as e:
        sys.exit(f"FATAL: lecture manifest : {e}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"FATAL: manifest JSON invalide : {e}")

    if not isinstance(manifest_dict, dict):
        sys.exit("FATAL: manifest doit être un objet JSON, pas array/scalar")

    required = [
        "app_id", "version", "issued_at", "min_from_version",
        "apk_url", "apk_host_whitelist", "apk_sha256",
        "force_update", "changelog",
    ]
    missing = [k for k in required if k not in manifest_dict]
    if missing:
        sys.exit(f"FATAL: champ(s) manquant(s) : {missing}")

    if "REPLACE_WITH" in json.dumps(manifest_dict):
        sys.exit("FATAL: un ou plusieurs champs contiennent encore 'REPLACE_WITH'. "
                 "Éditez le manifeste avant de signer.")

    canonical = _canonicalize(manifest_dict)
    sig = priv.sign(MANIFEST_DOMAIN + canonical)

    # Écriture ATOMIQUE : les bytes signés = les bytes écrits
    out_json = manifest_path
    out_sig = Path(str(manifest_path) + ".sig")
    out_json.write_bytes(canonical)
    out_sig.write_bytes(sig)

    try:
        json.loads(canonical.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        sys.exit(f"FATAL: round-trip canonique a produit un JSON invalide : {e}")

    print()
    print("=" * 78)
    print("MANIFESTE SIGNÉ")
    print("=" * 78)
    print(f"Fichier JSON     : {out_json} ({len(canonical)} bytes)")
    print(f"Signature        : {out_sig} ({len(sig)} bytes = ed25519)")
    print(f"Pubkey utilisée  : {ADMIN_PUBLIC_KEY_HEX}")
    print(f"Domaine signé    : {MANIFEST_DOMAIN!r}")
    print(f"SHA-256 manifest : {_sha256_hex(canonical)}")
    print()
    print("PROCHAINES ÉTAPES :")
    print("  1. Copier sur clé USB (PAS celle de la clé privée) :")
    print(f"       {out_json.name}")
    print(f"       {out_sig.name}")
    print("  2. Sur machine connectée, uploader vers :")
    print("       aresmaxima.com:/var/www/update/")
    print("  3. Vérifier depuis un poste client :")
    print("       curl -O https://aresmaxima.com/update/manifest.json")
    print("       curl -O https://aresmaxima.com/update/manifest.json.sig")


def cmd_rotate(args: argparse.Namespace) -> None:
    """Génère une nouvelle paire ed25519 (rotation de clé admin)."""
    _check_network_disconnected(args.allow_connected)

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    if args.out:
        out = Path(args.out)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(priv_hex + "\n")
        try:
            os.chmod(out, 0o600)
        except (OSError, NotImplementedError):
            pass
        print(f"Clé privée écrite : {out}")

    print()
    print("=" * 78)
    print("NOUVELLE PAIRE ADMIN (ROTATION)")
    print("=" * 78)
    print(f"Clé privée  (hex) : {priv_hex}")
    print(f"Clé publique (hex) : {pub_hex}")
    print()
    print("=" * 78)
    print("MISE À JOUR DES SOURCES (à appliquer AVANT release)")
    print("=" * 78)
    print()
    print("1. aegis-core/src/lib.rs — remplacer ADMIN_PUBLIC_KEY_BYTES :")
    print()
    print(_format_rust_pubkey(pub_hex))
    print()
    print("2. aegis_app/lib/updater_bridge.dart — remplacer _adminPublicKeyBytes :")
    print()
    print("   const List<int> _adminPublicKeyBytes = <int>[")
    bs = [int(pub_hex[i:i + 2], 16) for i in range(0, 64, 2)]
    for i in range(0, 32, 8):
        row = ", ".join(f"0x{b:02x}" for b in bs[i:i + 8])
        print(f"     {row},")
    print("   ];")
    print()
    print("3. aegis-core/src/updater.rs — vérifier que MANIFEST_DOMAIN est inchangé")
    print("   (pas de rotation du domaine : juste de la clé)")
    print()
    print("4. Commiter + rebuild + publier la nouvelle release signée avec la NOUVELLE clé.")
    print("   Les anciennes licences restent valides (vérifient la MÊME pubkey admin).")
    print()
    print("ATTENTION : si vous perdez cette nouvelle clé SANS avoir commité la nouvelle")
    print("pubkey, TOUS les clients actuels rejetteront les futures mises à jour.")


def cmd_destroy(args: argparse.Namespace) -> None:
    """Efface de façon sécurisée un fichier de clé privée."""
    if not args.confirm:
        sys.exit("FATAL: --confirm requis pour destruction définitive")
    _check_network_disconnected(args.allow_connected)

    key_path = Path(args.key)
    if not key_path.exists():
        sys.exit(f"FATAL: fichier introuvable : {key_path}")

    print(f"Suppression sécurisée : {key_path}")
    # Inline shred pour éviter dépendance externe
    size = key_path.stat().st_size
    with open(key_path, "r+b") as f:
        for _ in range(3):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    key_path.unlink()
    print("=" * 78)
    print("⚠️  CLÉ DÉTRUITE")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Signature de manifeste AEGIS (P0-A.8d.2).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--allow-connected", action="store_true",
        help="Outrepasse la vérification air-gapped (DÉCONSEILLÉ).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("template", help="Générer un template de manifeste")
    p.add_argument("--version", required=True)
    p.add_argument("--min-from", default="3.0.0")
    p.add_argument("--out", default="manifest.json")
    p.set_defaults(func=cmd_template)

    p = sub.add_parser("sign", help="Signer un manifeste existant")
    p.add_argument("--key", required=True)
    p.add_argument("--manifest", required=True)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("rotate", help="Générer une nouvelle paire admin")
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("destroy", help="Effacer une clé privée")
    p.add_argument("--key", required=True)
    p.add_argument("--confirm", action="store_true")
    p.set_defaults(func=cmd_destroy)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()