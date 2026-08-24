# AEGIS P2P v1.3.0-P2P-HEAVY - Zero-Trust Decentralized Platform 
 
![License: AGPLv3](https://img.shields.io/badge/License-AGPLv3-blue.svg) 
![Security Model](https://img.shields.io/badge/Security-Zero--Trust%%20%%7C%%20Zero--Trace-black.svg) 
![Build](https://img.shields.io/badge/Architecture-Rust%%20%%2B%%20Flutter-orange.svg) 
![Audit](https://img.shields.io/badge/Audit-PASSED%%20(v1.3.0)-brightgreen.svg) 
 
AEGIS est une plateforme de communication P2P ultra-securisee concue sur un modele de confiance nulle (Zero-Trust), d'empreinte memoire minimale (Zero-Trace), d'etancheite post-quantique et d'auto-destruction materielle sous contrainte. 
 
Le systeme repose sur un decouplage strict : 
* **aegis-core (Rust)** : Moteur cryptographique, gestionnaires de memoire verrouillee (mlock) et polymorphe, controle d'integrite noyau/TPM, declencheurs materiels de crise, reseau maille hors-ligne et protocole de purge materielle. 
* **aegis_app (Flutter / Dart)** : Coque d'affichage aveugle, isolee de la memoire vive cryptographique, protegee contre les captures d'ecran (FLAG_SECURE) et les fuites systeme. 
 
--- 
 
## Rapport d'Audit et Conformite Scellee 
 
L'application a passe l'audit de conformite intrusif avec succes. Le manifeste d'audit complet est scelle a la racine du depot (AUDIT_MANIFEST.json). 
 
* **Statut de l'audit** : PASSED 
* **Version certifiee** : v1.3.0-P2P-HEAVY 
* **Empreinte SHA-256 du manifeste** : dba403ad9eab4bee5ba5873b685b384eeedbaad3174f588e372f943b069ba173 
* **Fonctions FFI verifiees** : aegis_ingest_file_zero_disk, aegis_purge_ram_buffer, aegis_panic_silent_burn 
* **Profil Cargo** : panic = "abort", lto = true, strip = true 
 
--- 
 
## Licence et Distribution Officielle 
 
### Transparence du Code Source 
Le code source d'AEGIS P2P est publie sous licence GNU Affero General Public License v3.0 (AGPLv3) afin de permettre les audits cryptographiques independants, la verification de l'absence de portes derobees et la recherche en securite. 
 
### Binaires Officiels et Certifies 
La compilation requiert une chaine de compilation croisee complexe (Rust aarch64-linux-android, SDK Flutter, Android NDK et dependances C). 
 
Les binaires pre-compiles et signes numeriquement par Ares Maxima, accompagnes des garanties d'integrite officielle (SHA-256), sont distribues exclusivement sur notre plateforme officielle : 
 
https://aresmaxima.com 
 
--- 
 
## Matrice des Fonctionnalites et Specifications de Securite 
 
### 1. Hardening Memoire RAM et Attestation Materielle 
* **Verrouillage Memoire Precis (mlock)** : (src/secure_buffer.rs) Alignement dynamique sur la taille de page materielle de l'OS. Verrouillage en RAM via libc::mlock pour interdire toute ecriture dans le SWAP ou le fichier de pagination disque. Nettoyage deterministe par zeroize() avant deverrouillage (munlock). 
* **Obfuscation Memoire Polymorphe** : (src/polymorphic_ram.rs) Masquage XOR des tampons secrets avec un masque d'entropie glissant. Revision du masque a chaque lecture, effacement de l'ancien masque via .zeroize(), et re-obfusquation a une nouvelle empreinte binaire. 
* **Enclave Materielle et Measured Boot** : Interrogation des puces TPM 2.0 sous Linux ou StrongBox / Secure Enclave sous Android (src/keystore.rs). Refus d'initialisation en cas de detection de Rootkit ou Kernel altere. 
* **Coffre d'Isolation Opaque Rust / Dart** : Confinement total des secrets dans le binaire Rust. Derivation cryptographique PBKDF2 (Hmac-SHA256, 100k iterations) et dechiffrement AES-256-GCM. Flutter ne manipule qu'un pointeur opaque 64-bit non dereferencable en Dart. 
* **Interception Signaux OS et Canaris Anti-Cold Boot** : Ecoute dediee des signaux SIGINT / SIGTERM pour arret immediat (exit 137). Allocation de N tampons leurres ancres en RAM remplis d'entropie pour brouiller les scanners forensiques a chaud (Volatility/Rekall). 
 
### 2. Cryptographie Post-Quantique et Anti-Coercition 
* **Echange de Cles Hybride Kyber1024 / X25519** : Combinaison de la courbe elliptique X25519 et de l'algorithme a reseaux euclidiens Kyber-1024 via HKDF-SHA256. 
* **Protocole d'Auto-Destruction Materielle (Silent Burn)** : La saisie du PIN de crise (9999) ordonne l'invalidation definitive de la cle racine scellee dans la NVRAM du TPM 2.0 / StrongBox, detruit les conteneurs et force un exit 137 immediat. 
* **Brulure par Inactivite (Dead Man's Switch)** : Minuteur d'inactivite mecano-electrique rearticul‚ a chaque deverrouillage valide. Si aucun acces n'intervient sous 24h, le systeme execute automatiquement le Silent Burn. 
* **Declencheurs Physiques d'Urgence** : Execution immediate du Silent Burn lors d'anomalies physiques : retrait brutal de carte SIM/MicroSD, deconnexion USB suspecte pendant une extraction de donnees, ou secousse de crise captee par l'accelerometre. 
 
### 3. Protection Surface OS et Reseau OPSEC 
* **Protection Surface OS (FLAG_SECURE et Clipboard Bypass)** : Activation de FLAG_SECURE sur Android (interdiction des captures, enregistrements video et floutage dans le gestionnaire de taches). Desactivation de la selection interactive sur tous les champs sensibles. 
* **P2P Transport Hopping Dynamique** : Bascule a chaud automatique et deterministe entre Tor v3 (WAN), Direct WAN (libp2p KadDHT) et Reseau local isole (Air-Gapped / BLE / Wi-Fi Direct). 
* **Reseau Maille Hors-Ligne (Sneakernet)** : Propagation opportuniste de proche en proche des trames chiffrees de 512 octets via BLE / Wi-Fi Direct en zone de coupure reseau. Deduplication par Hash SHA-256 et limitation TTL a 10 sauts. 
* **Trafic d'Ombre a Debit Constant (Constant-Bitrate Padding)** : Enrobage de toutes les charges utiles dans des trames fixes de 512 octets transmises a intervalle regulier. Emission continue de trames leurres remplies de bruit blanc cryptographique. 
 
--- 
 
## Guide de Compilation et Distribution 
 
### Prerequis 
* Rust MSRV : 1.75.0+ 
* Flutter SDK : 3.19.0+ 
* Java JDK : Version 17 
 
### Execution 
powershell -ExecutionPolicy Bypass -File "force_build.ps1" 
 
--- 
 
## Politique de Divulgation des Vulnerabilites 
 
Contact PGP pour signalement chiffre : sales@aresmaxima.com 
Empreinte PGP : B0D6 C685 9A1A E443 4AC7 40CF C477 BDB6 9890 AB3C 
ID de Cle : 0xC477BDB69890AB3C 
