# AEGIS P2P v1.3.0-P2P-HEAVY - Zero-Trust Decentralized Platform

![License: Proprietary](https://img.shields.io/badge/License-Proprietary%20%7C%20Source--Available-red.svg)
![Security Model](https://img.shields.io/badge/Security-Zero--Trust%20%7C%20Zero--Trace-black.svg)
![Build](https://img.shields.io/badge/Architecture-Rust%20%2B%20Flutter-orange.svg)
![Audit](https://img.shields.io/badge/Audit-PASSED%20(v1.3.0)-brightgreen.svg)

AEGIS est une plateforme de communication P2P ultra-sécurisée conçue sur un modèle de confiance nulle (Zero-Trust), d'empreinte mémoire minimale (Zero-Trace), d'étanchéité post-quantique et d'auto-destruction matérielle sous contrainte.

Le système repose sur un découplage strict :
* **aegis-core (Rust)** : Moteur cryptographique, gestionnaires de mémoire verrouillée (mlock) et polymorphe, contrôle d'intégrité noyau/TPM, déclencheurs matériels de crise, réseau maillé hors-ligne et protocole de purge matérielle.
* **aegis_app (Flutter / Dart)** : Coque d'affichage aveugle, isolée de la mémoire vive cryptographique, protégée contre les captures d'écran (FLAG_SECURE) et les fuites système.

---

## Rapport d'Audit et Conformité Scellée

L'application a passé l'audit de conformité intrusif avec succès. Le manifeste d'audit complet est scellé à la racine du dépôt (AUDIT_MANIFEST.json).

* **Statut de l'audit** : PASSED
* **Version certifiée** : v1.3.0-P2P-HEAVY
* **Empreinte SHA-256 du manifeste** : dba403ad9eab4bee5ba5873b685b384eeedbaad3174f588e372f943b069ba173
* **Fonctions FFI vérifiées** : aegis_ingest_file_zero_disk, aegis_purge_ram_buffer, aegis_panic_silent_burn
* **Profil Cargo** : panic = "abort", lto = true, strip = true

---

## Licence, Code Source et Distribution Officielle

### Cadre Légal et Transparence du Code Source
> **Notice d'utilisation et de propriété intellectuelle :**  
> Ce dépôt contient l'implémentation de référence de l'architecture AEGIS. Le code source est rendu accessible public (*Source-Available*) exclusivement à des fins d'inspection, d'audit cryptographique indépendant et de vérification d'absence de portes dérobées.  
> 
> Alors que le papier scientifique (Whitepaper) associé est publié sous licence CC-BY 4.0, **le code source présent dans ce dépôt est distribué sous licence propriétaire (Tous Droits Réservés / All Rights Reserved)**. Toute modification, redistribution ou exploitation commerciale non autorisée est strictement interdite sans accord préalable.  
> 
> Pour toute demande de licence commerciale ou d'intégration entreprise, contactez : **sales@aresmaxima.com**

### Binaires Officiels et Certifiés
La compilation requiert une chaîne de compilation croisée complexe (Rust aarch64-linux-android, SDK Flutter, Android NDK et dépendances C).

Les binaires pré-compilés et signés numériquement par Ares Maxima, accompagnés des garanties d'intégrité officielle (SHA-256), sont distribués exclusivement sur notre plateforme officielle :

https://aresmaxima.com

---

## Matrice des Fonctionnalités et Spécifications de Sécurité

### 1. Hardening Mémoire RAM et Attestation Matérielle
* **Verrouillage Mémoire Précis (mlock)** : (`src/secure_buffer.rs`) Alignement dynamique sur la taille de page matérielle de l'OS. Verrouillage en RAM via `libc::mlock` pour interdire toute écriture dans le SWAP ou le fichier de pagination disque. Nettoyage déterministe par `zeroize()` avant déverrouillage (`munlock`).
* **Obfuscation Mémoire Polymorphe** : (`src/polymorphic_ram.rs`) Masquage XOR des tampons secrets avec un masque d'entropie glissant. Révision du masque à chaque lecture, effacement de l'ancien masque via `.zeroize()`, et re-obfuscation à une nouvelle empreinte binaire.
* **Enclave Matérielle et Measured Boot** : Interrogation des puces TPM 2.0 sous Linux ou StrongBox / Secure Enclave sous Android (`src/keystore.rs`). Refus d'initialisation en me de détection de Rootkit ou Kernel altéré.
* **Coffre d'Isolation Opaque Rust / Dart** : Confinement total des secrets dans le binaire Rust. Dérivation cryptographique PBKDF2 (Hmac-SHA256, 100k itérations) et déchiffrement AES-256-GCM. Flutter ne manipule qu'un pointeur opaque 64-bit non déférençable en Dart.
* **Interception Signaux OS et Canaris Anti-Cold Boot** : Écoute dédiée des signaux SIGINT / SIGTERM pour arrêt immédiat (exit 137). Allocation de N tampons leurres ancrés en RAM remplis d'entropie pour brouiller les scanners forensiques à chaud (Volatility/Rekall).

### 2. Cryptographie Post-Quantique et Anti-Coercition
* **Échange de Clés Hybride Kyber1024 / X25519** : Combinaison de la courbe elliptique X25519 et de l'algorithme à réseaux euclidiens Kyber-1024 via HKDF-SHA256.
* **Protocole d'Auto-Destruction Matérielle (Silent Burn)** : La saisie du PIN de crise (9999) ordonne l'invalidation définitive de la clé racine scellée dans la NVRAM du TPM 2.0 / StrongBox, détruit les conteneurs et force un exit 137 immédiat.
* **Brûlure par Inactivité (Dead Man's Switch)** : Minuteur d'inactivité mécano-électrique réarticulé à chaque déverrouillage valide. Si aucun accès n'intervient sous 24h, le système exécute automatiquement le Silent Burn.
* **Déclencheurs Physiques d'Urgence** : Exécution immédiate du Silent Burn lors d'anomalies physiques : retrait brutal de carte SIM/MicroSD, déconnexion USB suspecte pendant une extraction de données, ou secousse de crise captée par l'accéléromètre.

### 3. Protection Surface OS et Réseau OPSEC
* **Protection Surface OS (FLAG_SECURE et Clipboard Bypass)** : Activation de FLAG_SECURE sur Android (interdiction des captures, enregistrements vidéo et floutage dans le gestionnaire de tâches). Désactivation de la sélection interactive sur tous les champs sensibles.
* **P2P Transport Hopping Dynamique** : Bascule à chaud automatique et déterministe entre Tor v3 (WAN), Direct WAN (libp2p KadDHT) et Réseau local isolé (Air-Gapped / BLE / Wi-Fi Direct).
* **Réseau Maillé Hors-Ligne (Sneakernet)** : Propagation opportuniste de proche en proche des trames chiffrées de 512 octets via BLE / Wi-Fi Direct en zone de coupure réseau. Déduplication par Hash SHA-256 et limitation TTL à 10 sauts.
* **Trafic d'Ombre à Débit Constant (Constant-Bitrate Padding)** : Enrobage de toutes les charges utiles dans des trames fixes de 512 octets transmises à intervalle régulier. Émission continue de trames leurres remplies de bruit blanc cryptographique.

---

## Guide de Compilation et Distribution

### Prérequis
* Rust MSRV : 1.75.0+
* Flutter SDK : 3.19.0+
* Java JDK : Version 17

### Exécution
```powershell
powershell -ExecutionPolicy Bypass -File "force_build.ps1"
