# AEGIS P2P — Zero-Trust Decentralized Communication

![License: AGPLv3](https://img.shields.io/badge/License-AGPLv3-blue.svg)
![Security Model](https://img.shields.io/badge/Security-Zero--Trust%20%7C%20Zero--Trace-black.svg)
![Build](https://img.shields.io/badge/Architecture-Rust%20%2B%20Flutter-orange.svg)

AEGIS P2P is an ultra-secure, zero-persistence communication platform engineered with a Pure Rust core (`aegis-core`) and an isolated Flutter interface. 

Designed for maximum operational security (OPSEC), AEGIS operates on a strict **Zero-Server / Pure P2P** model with post-quantum key exchange, anti-forensic RAM protection, and hardware-level crisis triggers.

---

## 🛡️ Core Security Architecture

* **Zero-Server & Pure P2P:** No central servers, relay databases, or centralized metadata storage.
* **RAM-Only Execution:** Zero disk persistence. Secrets are locked in memory (`mlock`) and deterministically wiped (`zeroize`).
* **Anti-Forensics & Cold-Boot Protection:** Polymorphic RAM obfuscation pools and memory noise canaries to blind forensic scanners (Volatility/Rekall).
* **Post-Quantum Key Exchange:** Hybrid Kyber1024 + X25519 key exchange to prevent retroactive quantum decryption.
* **Censorship Bypass:** Integrated pure-Rust Tor v3 client and dynamic multi-transport hopping (Tor WAN, Direct KadDHT, Air-Gapped Sneakernet Mesh).
* **Emergency Hardware Triggers:** Instant "Silent Burn" execution via crisis PIN (`9999`), dead man's switch (24h inactivity), or hardware sensor anomalies (SIM removal, USB disconnection, accelerometer shocks).
* **Clipboard & Capture Isolation:** Enforced `FLAG_SECURE` screen protection and complete clipboard bypass.

---

## ⚖️ License & Official Distribution

### Source Code Transparency
The source code of AEGIS P2P is made public under the **GNU Affero General Public License v3.0 (AGPLv3)** to allow independent cryptographic audits, zero-backdoor verification, and research.

### Official Binaries & Signed Releases
Building the application from source requires a complex cross-compilation environment (Rust `aarch64-linux-android`, Flutter SDK, Android NDK, and C dependencies). 

Pre-compiled, digitally signed binaries (APKs) certified by **Ares Maxima**, along with official integrity guarantees (SHA-256 hashes) and continuous updates, are distributed exclusively on our official platform:

👉 **[Purchase Official AEGIS P2P License](https://aresmaxima.com)**

*Notice: Commercial redistribution, re-packaging, or re-branding of pre-compiled binaries without an explicit commercial license from Ares Maxima is strictly prohibited under the AGPLv3 license.*

---

## 🏗️ Architecture & Modules Overview

```text
aegis-core/src/           # Pure-Rust Security & Cryptographic Core
├── crypto.rs             # Memory integrity & ptrace checks
├── crypto_pq.rs          # Hybrid Kyber1024 / X25519 post-quantum exchange
├── deadman.rs            # Inactivity timer (Dead Man's Switch 24h)
├── hardware_triggers.rs  # Hardware sensor anomaly interception (SIM/USB/Motion)
├── keystore.rs           # TPM 2.0 / StrongBox Hardware Keystore interface
├── lib.rs                # FFI entry points & APK signature verification
├── mesh.rs               # Offline P2P Sneakernet Mesh (BLE/Wi-Fi Direct)
├── network.rs            # Constant-bitrate traffic shaper (512-byte fixed frames)
├── panic.rs              # Silent Burn & NVRAM wipe routines
├── polymorphic_ram.rs    # Sliding entropy mask obfuscation pools
├── secure_buffer.rs      # Page-aligned mlock / zeroize buffers
├── session.rs            # FFI Opaque Session Vault (Rust/Dart heap isolation)
├── signals.rs            # OS signal interception & memory noise canaries
├── stegano.rs            # Invisible Unicode steganography (Drowning)
├── storage.rs            # RAM-only volatile database
└── transport.rs          # Dynamic transport hopping router

aegis_app/lib/            # Blind Flutter UI & FFI Wrapper
├── main.dart             # LockScreen, FLAG_SECURE, & Multi-language App Engine
└── services/
    └── crypto_service.dart # Dart PBKDF2/AES-GCM wrapper over opaque pointer

🛠️ Build & Toolchain Requirements
To build AEGIS from source, ensure your environment meets the following specifications:

Rust MSRV: 1.75.0+

Flutter SDK: 3.19.0+

Java JDK: Version 17 (JDK 17.0.10)

Android SDK / NDK: compileSdk = 36 | NDK: 27.0.12077973 (aarch64-linux-android)

Kotlin Plugin: 2.1.0

System Build Libraries: clang, libssl-dev, pkg-config, libtss2-dev

Compilation Procedure
Build Native Rust Core:

cd aegis-core
cargo build --target aarch64-linux-android --release

Sync Shared Native Library:

# Windows (PowerShell)
Copy-Item "target/aarch64-linux-android/release/libaegis_core.so" -Destination "../aegis_app/android/app/src/main/jniLibs/arm64-v8a/libaegis_core.so"

# Linux / macOS
cp target/aarch64-linux-android/release/libaegis_core.so ../aegis_app/android/app/src/main/jniLibs/arm64-v8a/libaegis_core.so

Build Flutter APK:

cd ../aegis_app
flutter clean
flutter pub get
flutter build apk --release --split-per-abi

Target Output: aegis_app/build/app/outputs/flutter-apk/app-arm64-v8a-release.apk

Forensic Memory Audit & Validation
Verify memory sanitization and zero-trace execution using the built-in test suite:

cd aegis-core

# Unit & Cryptographic Tests
cargo test --all-targets -- --nocapture

# Undefined Behavior Audit (Miri)
cargo +nightly miri test

# AddressSanitizer & Memory Leak Verification
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu

# Valgrind RAM Leak Audit
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./target/release/deps/aegis_core-*

📬 Security Policy & Vulnerability Disclosure
If you discover a security vulnerability or anomalous behavior in AEGIS, do not open a public issue.

Encrypted Reporting Procedure
Obtain our official PGP Public Key (SECURITY_KEY.asc).

Fingerprint: B0D6 C685 9A1A E443 4AC7 40CF C477 BDB6 9890 AB3C

Key ID: 0xC477BDB69890AB3C

Encrypt your report and PoC using the key.

Submit the encrypted advisory to: sales@aresmaxima.com

A confirmation with a tracking ticket will be returned within 48 business hours.