# 🛡️ AEGIS P2P v3.7.0 — High-Assurance Zero-Disk Mobile Messenger

[![CI Assurance](https://img.shields.io/badge/Formal_CI-14%2F14_Passing-4ade80?style=flat-square&logo=githubactions&logoColor=black)](https://github.com/AresMaxima/aegis-p2p/actions)
[![SLSA Provenance](https://img.shields.io/badge/Supply_Chain-SLSA_Build_Provenance-FCBE0B?style=flat-square&logo=sigstore&logoColor=black)](https://github.com/AresMaxima/aegis-p2p/attestations)
[![Post-Quantum](https://img.shields.io/badge/NIST_PQC-SPQR_ML--KEM--1024_%2B_ML--DSA--87-4ade80?style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)
[![COTS Status](https://img.shields.io/badge/U.S._EAR-ECCN_5D992.c_COTS-blue?style=flat-square)](https://aresmaxima.com/aegis-p2p-messagerie-securisee-anti-forensique/)
[![ANSSI](https://img.shields.io/badge/ANSSI_Registration-n%C2%B0_35567570-informational?style=flat-square)](https://aresmaxima.com/aegis-p2p-messagerie-securisee-anti-forensique/)

**AEGIS P2P v3.7.0** (`SKU: AM-AEGIS-P2P-370`) is a serverless, SIM-less, peer-to-peer encrypted mobile communication suite engineered around a strict **Zero-Disk Volatile RAM** architecture, **Continuous Post-Quantum Ratcheting (SPQR)**, and **Android StrongBox HSM Hardware Binding**.

> **Official Portal & HSM-Bound Licensing:** [https://aresmaxima.com/aegis-p2p-messagerie-securisee-anti-forensique/](https://aresmaxima.com/aegis-p2p-messagerie-securisee-anti-forensique/)

---

## 🔍 Don't Trust Us, Verify (Cryptographic & SLSA Supply-Chain Proofs)

Every official **AEGIS P2P v3.7.0** binary is compiled deterministically on ephemeral GitHub Actions runners, verified via independent **Bit-for-Bit Vendor A/B rebuilds (Debian vs. Ubuntu 24.04)**, and sealed with cryptographic **Sigstore / SLSA Build Provenance**.

### 1. Official v3.7.0 Reference Digests (`arm64-v8a`)

| Artifact | SHA-256 Digest |
| :--- | :--- |
| **`aegis-v3.7.apk`** (Signed Release APK) | `bd7005e01d05df98338208e4d6cd6a003a059c7651e4cef53fe6ee4a2cb048fa` |
| **`libaegis_core.so`** (Rust Native Engine) | `c8fcd620135f2213faf87d436993f35aa30d5a9811d0b22ecd68c70042fb70c4` |
| **APK Signing Certificate (SHA-256)** | `c3e55c0b0a9369bba0fb738c9277aa09fa928924bd5fa40ad32ecf85faca88db` |

### 2. One-Line Client Verification Commands

```bash
# 1. Verify SHA-256 binary integrity (Linux / macOS)
sha256sum -c aegis-v3.7.apk.sha256

# 2. Verify cryptographic SLSA Build Provenance against GitHub's Sigstore transparency log
gh attestation verify aegis-v3.7.apk --repo AresMaxima/aegis-p2p
gh attestation verify libaegis_core.so --repo AresMaxima/aegis-p2p

# 3. Verify X.509 APK signing certificate fingerprint (must match c3e55c0b...ca88db)
apksigner verify --print-certs aegis-v3.7.apk
```

---

## ⚙️ Core Security Architecture (v3.7.0 — Milestones C89 to C96)

* **Zero-Disk Polymorphic RAM Engine:** Zero SQLite message databases, zero flash media caches. Payloads reside exclusively in XOR-masked dual-rail volatile RAM buffers with integrity canaries and physical `/proc/self/mem` zeroization verification (**C94**).
* **Continuous Stateful Post-Quantum Ratchet (SPQR — C95):** Hybrid initial key agreement (`ML-KEM-1024` NIST FIPS 203 + `X25519`) reinforced by continuous intra-session `ML-KEM-1024` epoch re-encapsulation (`#1 → #N` fragmented across `4 × 512B` cells for active Post-Compromise Security) and hybrid **`ML-DSA-87` (FIPS 204) + `Ed25519`** signatures.
* **StrongBox HSM Binding & Mutual X.509 Attestation (C89 / C91 / C94):** Offline `Ed25519` license binding to the handset's non-exportable hardware `ECDSA P-256` StrongBox keypair (*Fail-Closed*), peer-to-peer mutual X.509 hardware attestation (`VerifiedBoot GREEN`, `security_level=2`), and optional external **YubiKey 5 NFC** sealing.
* **4 Autonomous & Anti-DPI Transports (C90 / C92 / C93 / C96):**
  1. **Embedded Tor (`Arti` `rustls+ring`) + Stealth `HTTP/3 MASQUE` (RFC 9297) + `TLS 1.3 ECH` + `GREASE`** & **512B Chaff cover traffic** against state-level Deep Packet Inspection (DPI).
  2. **0-RF Optical Air-Gap Bridge (15 fps Luby Fountain QR)** for bidirectional communication in full Airplane Mode with zero radio emissions.
  3. **Wi-Fi Direct** high-throughput local peer-to-peer link without routers.
  4. **BLE Mesh** (`TTL=5`, 60s deduplication) + self-burning hourly **RAM Dead-Drops**.
* **Anti-Coercion & Media Sanitization:** Plausible **Decoy PIN** workspace under physical duress, instant **Panic Kill Switch** (60s background auto-purge), automatic **EXIF stripping**, **Anti-PRNU** camera sensor noise attenuation, VRAM **BlindView**, and global `FLAG_SECURE`.

---

## 🧪 14/14 Automated Formal Verification & CI Assurance

Every release commit must pass **14 independent verification pipelines** before packaging:
1. **AWS Kani Model Checking:** Mathematical absence of panics/overflows across critical primitives.
2. **Rust Miri (5 Suites):** Exhaustive Undefined Behavior (UB), pointer provenance, and concurrency verification.
3. **Continuous Fuzzing (5 LibFuzzer Targets):** Wire parsers, steganography, ratchet frames, and FFI boundaries.
4. **Valgrind / Linux `mmap` Lock Audit:** Zero residual memory leaks across locked volatile pages.
5. **Bit-for-Bit Reproducible NDK Build:** Independent Vendor A (Debian) vs. Vendor B (Ubuntu 24.04) `.so` hash match + CycloneDX SBOM (`aegis-core.cdx.json`).
6. **RustSec, Clippy (`all-targets`), TPM2 & JNI Symbol Export Gates:** 0 active vulnerabilities across 503 crates, 52/52 verified FFI wrappers.

---

## 📚 Official Multilingual Documentation (7 Languages: FR / EN / ES / IT / PL / UK / AR)

All official `v3.7.0` operational, technical, and legal manuals are available under [`GUIDE UTILISATEUR/`](./GUIDE%20UTILISATEUR/):

* 📄 [**Internal Security Audit Report (v3.7.0)**](./GUIDE%20UTILISATEUR/AUDIT%20INTERNE/AEGIS_v3.7.0_AUDIT_REPORT_MULTI.html)
* 📊 [**Technical Proofs & Competitive Benchmark (v3.7.0)**](./GUIDE%20UTILISATEUR/TECH%20DATAS/AEGIS_v3.7.0_TECH_DATAS_MULTI.html)
* 🛡️ [**Operations Guide & OpSec Manual (v3.7.0)**](./GUIDE%20UTILISATEUR/TECH%20SHEET/AEGIS_v3.7.0_OpSec_MULTI.html)
* 🚀 [**Quick Start User Guide (v3.7.0)**](./GUIDE%20UTILISATEUR/MANUAL/AEGIS_v3.7.0_USER_GUIDE_MULTI.html)
* ❓ [**Step-by-Step Operational Guide & 21 FAQs (v3.7.0)**](./GUIDE%20UTILISATEUR/FAQ%20USER/FAQ_MULTI.HTML)
* 💼 [**Executive Commercial Brochure (v3.7.0)**](./GUIDE%20UTILISATEUR/BUSINESS%20BROCHURE/AEGIS_v3.7.0_COMMERCIAL_BROCHURE_MULTI.html)
* ⚖️ [**COTS End-User License Agreement — HSM Bound (v3.7.0)**](./GUIDE%20UTILISATEUR/LICENSE%20AEGIS/LICENSE%20AEGIS.html)

---

## ⚖️ Regulatory Classification & Intellectual Property Notice

* **Civil COTS Export Status:** Standalone civilian Commercial Off-The-Shelf (COTS) information security software classified under **U.S. EAR ECCN 5D992.c (Mass Market, 15 CFR 740.17(b)(1))** — non-ITAR / non-EU ML11. Registered with the French **ANSSI** under file **n° 35567570**.
* **Sanctions Compliance:** No APK distribution or offline HSM Enrollment Seal activation is provided to embargoed jurisdictions or parties listed on U.S. OFAC SDN, BIS Denied Persons / Entity List, or EU sanctions lists.
* **Commercial Operator & Ownership:** Exclusively operated and distributed by **AresMaxima LLC** (New Mexico, USA — USPPI) under license. Source code is published for transparency and security auditability only; no open-source license is granted.

**Copyright © 2026 AresMaxima LLC and its Licensors. All Rights Reserved.**
