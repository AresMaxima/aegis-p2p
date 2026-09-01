# Politique de Sécurité & Programme Bug Bounty AEGIS v2.2-GA

## 1. Engagement de Divulgation Responsable
Le projet AEGIS s'appuie sur la transparence et le contrôle communautaire (Protocole BRAVO) pour garantir l'intégrité de ses composants natifs (`aegis-core`, `aegis_watchdog`).

## 2. Périmètre du Bug Bounty
* **Moteur Natif (`aegis-core`)** : Dépassement de tampon, fuite de clé en mémoire RAM, contournement de `PanicPurge`.
* **Sidecar Watchdog (`aegis_watchdog`)** : Contournement du blocage NVRAM TPM 2.0 lors d'un `SIGKILL`.
* **Transport P2P / Tor** : Faiblesse de constante temporelle (*constant-time*), fuite de métadonnées de trame.

## 3. Récompenses & Reconnaissance
* **Hall of Fame** : Inscription permanente du nom/pseudonyme du chercheur au registre des contributeurs.
* **CVE Attribution** : Demande et attribution officielle de numéro CVE auprès du MITRE.
* **Peer Recognition** : Mention explicite dans les publications académiques associées.

## 4. Signalement
Signalement chiffré PGP à : `security@aegis-p2p.org`.
