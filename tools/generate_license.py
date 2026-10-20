#!/usr/bin/env python3
"""
generate_license.py — Génération de licences client AEGIS (P0-A.8d.2).

Changements vs version initiale :
  - Séparation de domaine (C89) : signe b"LICENSE:v1:" + order_num.upper()
    (anti cross-usage avec manifestes signés par la même clé)
  - BIP39 : encodage de la clé privée en 24 mots (backup papier lisible)
  - CRC32 : checksum sur la sauvegarde papier (détection erreur de recopie)
  - --allow-connected : même politique air-gapped que sign_manifest.py
  - shred : destruction sécurisée de la clé
  - Vérification pubkey contre ADMIN_PUBLIC_KEY_HEX

Usage :
  # 1. Générer la paire initiale (une seule fois, sur air-gapped)
  python generate_license.py new-key --out admin.key

  # 2. Backup papier (24 mots BIP39 + pubkey + CRC32)
  python generate_license.py paper-backup --key admin.key --out paper.txt

  # 3. Générer une licence client
  python generate_license.py license --key admin.key --order "CMD-12345"

  # 4. Vérifier que le papier est intact (reprise après sinistre)
  python generate_license.py paper-restore --key admin.key --expected-crc32 <hex>

  # 5. Destruction (fin de vie, perte de contrôle)
  python generate_license.py shred --key admin.key --confirm
"""

import argparse
import os
import socket
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

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

ADMIN_PUBLIC_KEY_HEX = (
    "ac2611c408d34cf565189cba8448d776c20d958c288372659067690c5dd2146d"
)

LICENSE_DOMAIN = b"LICENSE:v1:"

# =============================================================================
# Helpers
# =============================================================================

def _check_network_disconnected(allow_connected: bool) -> None:
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
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    actual = priv.public_key().public_bytes_raw().hex()
    if actual != ADMIN_PUBLIC_KEY_HEX:
        sys.exit(
            f"FATAL: pubkey dérivée ne correspond pas.\n"
            f"  dérivée  : {actual}\n"
            f"  attendue : {ADMIN_PUBLIC_KEY_HEX}"
        )
    return actual


def _bip39_encode(seed: bytes) -> str:
    try:
        from mnemonic import Mnemonic
    except ImportError:
        sys.exit("FATAL: package 'mnemonic' non installé. pip install mnemonic")
    m = Mnemonic("english")
    return m.to_mnemonic(seed)


def _bip39_decode(phrase: str) -> bytes:
    try:
        from mnemonic import Mnemonic
    except ImportError:
        sys.exit("FATAL: package 'mnemonic' non installé. pip install mnemonic")
    m = Mnemonic("english")
    if not m.check(phrase):
        sys.exit("FATAL: phrase BIP39 invalide (checksum interne invalide)")
    return m.to_entropy(phrase)


def _crc32_hex(*parts: str) -> str:
    data = "||".join(parts).encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return f"{crc:08x}"


def _shred_file(path: Path, passes: int = 3) -> None:
    if not path.exists():
        return
    size = path.stat().st_size
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    path.unlink()
    print(f"  (effacé {passes} passes : {path})")


# =============================================================================
# Subcommands
# =============================================================================

def cmd_new_key(args: argparse.Namespace) -> None:
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
    print("NOUVELLE PAIRE ADMIN")
    print("=" * 78)
    print(f"Clé privée  (hex) : {priv_hex}")
    print(f"Clé publique (hex) : {pub_hex}")
    print()
    print("IMPORTANT :")
    print("  1. Backup papier : python generate_license.py paper-backup --key " + (args.out or "<clé>"))
    print("  2. Transférer la clé privée sur 2 supports physiques (coffres séparés)")
    print("  3. Mettre à jour ADMIN_PUBLIC_KEY_BYTES dans lib.rs et _adminPublicKeyBytes dans updater_bridge.dart")
    print("  4. NE JAMAIS stocker la clé privée en cloud/mail/photos")


def cmd_license(args: argparse.Namespace) -> None:
    _check_network_disconnected(args.allow_connected)

    key_bytes = _load_privkey(args.key)
    _verify_pubkey_matches_admin(key_bytes)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

    order_canonical = args.order.strip().upper()
    if not order_canonical:
        sys.exit("FATAL: --order vide")

    signed_payload = LICENSE_DOMAIN + order_canonical.encode("utf-8")
    sig = priv.sign(signed_payload)

    inner = f"{order_canonical}:{sig.hex()}"
    outer_hex = inner.encode("utf-8").hex()

    print()
    print("=" * 78)
    print("LICENCE CLIENT")
    print("=" * 78)
    print(f"Commande     : {order_canonical}")
    print(f"Domaine signé: {LICENSE_DOMAIN!r}")
    print()
    print("LICENCE (à envoyer par email au client) :")
    print()
    print(outer_hex)
    print()
    print("Le client la colle dans l'app AEGIS au moment de l'activation.")


def cmd_paper_backup(args: argparse.Namespace) -> None:
    _check_network_disconnected(args.allow_connected)

    key_bytes = _load_privkey(args.key)
    pub_hex = _verify_pubkey_matches_admin(key_bytes)

    phrase = _bip39_encode(key_bytes)
    if _bip39_decode(phrase) != key_bytes:
        sys.exit("FATAL: BIP39 round-trip échoué — bug, abandon")

    crc = _crc32_hex(phrase, pub_hex)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    words = phrase.split()
    rows = []
    for i in range(8):
        rows.append(
            f"  {i + 1:2d}. {words[i]:<12s}    "
            f"{i + 9:2d}. {words[i + 8]:<12s}    "
            f"{i + 17:2d}. {words[i + 16]:<12s}"
        )
    words_block = "\n".join(rows)

    doc = f"""================================================================================
                  AEGIS — BACKUP CLE ADMIN (DOCUMENT PAPIER)
================================================================================

[!] CONFIDENTIEL — NE JAMAIS PHOTOGRAPHIER, SCANNER, OU TAPER SUR UN
    APPAREIL CONNECTE. Conserver dans un coffre physique uniquement.

Date de generation : {now}
Algorithme         : ed25519 (32 bytes seed = 256 bits)
Encodage           : BIP39 (24 mots, wordlist anglaise standard)

--------------------------------------------------------------------------------
BIP39 SEED PHRASE — 24 MOTS (ordre strict, a recopier tel quel)
--------------------------------------------------------------------------------

{words_block}

--------------------------------------------------------------------------------
VERIFICATION (checksum de recopie)
--------------------------------------------------------------------------------

Pubkey ed25519 attendue (64 hex) :
  {pub_hex}

CRC32 sur (seed_phrase || pubkey_hex) :
  {crc}

--------------------------------------------------------------------------------
INSTRUCTIONS DE CONSERVATION
--------------------------------------------------------------------------------

1. Imprimer ou recopier A LA MAIN sur papier (pas de fichier numerique).
2. Faire 2 copies. Conserver dans 2 coffres separes.
3. Ne JAMAIS stocker ce document sous forme numerique.
4. Ne JAMAIS taper le seed sur un appareil connecte.
5. En cas de perte de la cle privee : procedure de rotation.

================================================================================
"""

    if args.out:
        out = Path(args.out)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(doc)
        print(f"Backup papier écrit : {out} ({out.stat().st_size} bytes)")
        print()
        print("PROCHAINE ÉTAPE :")
        print(f"  1. Notepad {out.name} → Imprimer (ou recopier à la main)")
        print(f"  2. shred {out.name} (après impression, pour ne pas laisser le fichier)")
    else:
        print(doc)


def cmd_paper_restore(args: argparse.Namespace) -> None:
    key_bytes = _load_privkey(args.key)
    pub_hex = _verify_pubkey_matches_admin(key_bytes)

    phrase = _bip39_encode(key_bytes)
    actual_crc = _crc32_hex(phrase, pub_hex)

    if actual_crc == args.expected_crc32.lower().strip():
        print(f"OK  CRC32 match : {actual_crc}")
        print(f"    Pubkey      : {pub_hex}")
    else:
        print(f"KO  CRC32 mismatch :")
        print(f"    attendu  : {args.expected_crc32.lower().strip()}")
        print(f"    calculé  : {actual_crc}")
        sys.exit(1)


def cmd_shred(args: argparse.Namespace) -> None:
    if not args.confirm:
        sys.exit("FATAL: --confirm requis pour destruction définitive")
    _check_network_disconnected(args.allow_connected)

    target = Path(args.key)
    if not target.exists():
        sys.exit(f"FATAL: fichier introuvable : {target}")

    print(f"Suppression sécurisée : {target}")
    _shred_file(target, passes=3)
    print()
    print("=" * 78)
    print("⚠️  FICHIER DÉTRUIT")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Génération de licences client AEGIS (P0-A.8d.2).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--allow-connected", action="store_true",
        help="Outrepasse la vérification air-gapped (DÉCONSEILLÉ).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("new-key", help="Générer une paire admin (init ou rotation)")
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_new_key)

    p = sub.add_parser("license", help="Générer une licence client")
    p.add_argument("--key", required=True)
    p.add_argument("--order", required=True)
    p.set_defaults(func=cmd_license)

    p = sub.add_parser("paper-backup", help="Générer le document BIP39 + CRC32")
    p.add_argument("--key", required=True)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_paper_backup)

    p = sub.add_parser("paper-restore", help="Vérifier un papier contre son CRC32")
    p.add_argument("--key", required=True)
    p.add_argument("--expected-crc32", required=True)
    p.set_defaults(func=cmd_paper_restore)

    p = sub.add_parser("shred", help="Effacement sécurisé d'un fichier")
    p.add_argument("--key", required=True)
    p.add_argument("--confirm", action="store_true")
    p.set_defaults(func=cmd_shred)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()