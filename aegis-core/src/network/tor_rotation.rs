//! aegis-core/src/network/tor_rotation.rs
//!
//! Gestionnaire de rotation de circuit Tor — déclencheurs événementiels.
//!
//! ─────────────────────────────────────────────────────────────────────
//! DÉCISIONS D43, D43-bis, D43-ter, D43-quater (02/10/2026) :
//!
//!   • Volume       : 512 KiB ± jitter CSPRNG 0-128 KiB
//!   • Inactivité   : 15 s sans échange
//!   • Réseau       : changement (Wi-Fi ↔ 4G) → rotation immédiate
//!   • Anomalie     : >3 erreurs consécutives → rotation
//!
//! Le jitter empêche un adversaire de prédire le moment exact de la
//! rotation par analyse de flux. La plage 0-128 KiB fait varier le
//! seuil effectif entre 512 KiB et 640 KiB.
//!
//! Générateur : OsRng (appel direct au CSPRNG noyau, /dev/urandom ou
//! équivalent). Pas de thread_rng local — chaque tirage de jitter est
//! une requête noyau indépendante, imprévisible même si l'état d'un
//! CSPRNG utilisateur était compromis.
//!
//! Ce module est **indépendant** du transport Tor lui-même : il ne fait
//! que calculer QUAND la rotation doit avoir lieu. Le déclenchement réel
//! (fermeture de circuit + réouverture) est fait dans `tor.rs` (P0-A.1d).
//! ─────────────────────────────────────────────────────────────────────

use rand::rngs::OsRng;
use rand::RngCore;
use std::time::{Duration, Instant};

/// Volume de base avant rotation : 512 KiB.
pub const VOLUME_BASE_BYTES: u64 = 512 * 1024;

/// Jitter maximal ajouté au seuil de volume : 128 KiB.
/// Le seuil effectif est donc entre 512 KiB et 640 KiB.
pub const VOLUME_JITTER_MAX_BYTES: u64 = 128 * 1024;

/// Inactivité maximale avant rotation : 15 s.
pub const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(15);

/// Nombre d'erreurs consécutives déclenchant une rotation.
pub const MAX_CONSECUTIVE_ERRORS: u32 = 3;

/// Raison d'une rotation de circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// Seuil de volume atteint (512 KiB + jitter).
    VolumeThreshold,

    /// Inactivité prolongée (15 s sans échange).
    Inactivity,

    /// Changement de réseau détecté (Wi-Fi ↔ 4G).
    NetworkChange,

    /// Trop d'erreurs consécutives (anomalie possible).
    ConsecutiveErrors,
}

impl RotationReason {
    /// Message lisible pour logs internes.
    /// **Ne jamais logger le contexte réseau associé** (fuite d'info).
    pub fn as_str(&self) -> &'static str {
        match self {
            RotationReason::VolumeThreshold => "volume_threshold",
            RotationReason::Inactivity => "inactivity",
            RotationReason::NetworkChange => "network_change",
            RotationReason::ConsecutiveErrors => "consecutive_errors",
        }
    }
}

/// Gestionnaire de rotation de circuit Tor.
///
/// Ne réalise PAS la rotation lui-même — il indique quand elle doit
/// avoir lieu via `should_rotate()`. Le transport (`tor.rs`) est
/// responsable de fermer/rouvrir le circuit.
pub struct TorCircuitRotation {
    /// Seuil effectif courant (512 KiB + jitter individuel).
    /// Régénéré à chaque `reset_after_rotation()`.
    volume_threshold: u64,

    /// Volume cumulé depuis la dernière rotation.
    bytes_since_rotation: u64,

    /// Dernier timestamp d'activité (échange réseau réussi).
    last_activity: Instant,

    /// Nombre d'erreurs consécutives (reset sur succès).
    consecutive_errors: u32,

    /// Flag : changement réseau détecté → rotation forcée.
    network_changed: bool,
}

impl TorCircuitRotation {
    /// Crée un nouveau gestionnaire avec un jitter initial OsRng.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            volume_threshold: Self::generate_jittered_threshold(),
            bytes_since_rotation: 0,
            last_activity: now,
            consecutive_errors: 0,
            network_changed: false,
        }
    }

    /// Génère un seuil jitté : `VOLUME_BASE_BYTES + [0, VOLUME_JITTER_MAX_BYTES)`.
    ///
    /// Source : `OsRng` — appel direct au CSPRNG du noyau (getrandom).
    /// Aucun état local à compromettre.
    fn generate_jittered_threshold() -> u64 {
        let mut rng = OsRng;
        let jitter = rng.next_u64() % VOLUME_JITTER_MAX_BYTES;
        VOLUME_BASE_BYTES + jitter
    }

    /// Enregistre `n` octets envoyés depuis la dernière rotation.
    pub fn record_bytes_sent(&mut self, n: u64) {
        self.bytes_since_rotation = self.bytes_since_rotation.saturating_add(n);
    }

    /// Enregistre une activité (échange réseau réussi).
    /// Reset le timer d'inactivité.
    pub fn record_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Enregistre une erreur réseau (I/O, timeout, handshake).
    pub fn record_error(&mut self) {
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
    }

    /// Enregistre un succès réseau — reset le compteur d'erreurs.
    pub fn record_success(&mut self) {
        self.consecutive_errors = 0;
    }

    /// Signale un changement de réseau (Wi-Fi → 4G ou inverse).
    /// Force la rotation au prochain `should_rotate()`.
    pub fn invalidate_on_network_change(&mut self) {
        self.network_changed = true;
    }

    /// Évalue si une rotation doit avoir lieu.
    ///
    /// Priorité des déclencheurs (ordre décroissant) :
    ///   1. NetworkChange (le plus urgent — circuit cassé)
    ///   2. ConsecutiveErrors (anomalie sécurité)
    ///   3. VolumeThreshold (secret accumulé)
    ///   4. Inactivity (circuit peut être frais)
    pub fn should_rotate(&self, now: Instant) -> Option<RotationReason> {
        // 1. Changement réseau = circuit cassé, rotation obligatoire.
        if self.network_changed {
            return Some(RotationReason::NetworkChange);
        }

        // 2. Trop d'erreurs consécutives = anomalie suspecte.
        if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
            return Some(RotationReason::ConsecutiveErrors);
        }

        // 3. Volume atteint.
        if self.bytes_since_rotation >= self.volume_threshold {
            return Some(RotationReason::VolumeThreshold);
        }

        // 4. Inactivité prolongée.
        if now.duration_since(self.last_activity) >= INACTIVITY_TIMEOUT {
            return Some(RotationReason::Inactivity);
        }

        None
    }

    /// Réinitialise l'état après une rotation effective.
    /// Régénère un nouveau jitter (OsRng).
    pub fn reset_after_rotation(&mut self, now: Instant) {
        self.volume_threshold = Self::generate_jittered_threshold();
        self.bytes_since_rotation = 0;
        self.last_activity = now;
        self.consecutive_errors = 0;
        self.network_changed = false;
    }

    // ===== Accesseurs (pour tests & debug) =====

    /// Seuil effectif courant (bytes).
    pub fn current_volume_threshold(&self) -> u64 {
        self.volume_threshold
    }

    /// Volume cumulé depuis la dernière rotation.
    pub fn bytes_since_rotation(&self) -> u64 {
        self.bytes_since_rotation
    }

    /// Nombre d'erreurs consécutives.
    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors
    }

    /// Timestamp de dernière activité.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Flag de changement réseau.
    pub fn network_changed(&self) -> bool {
        self.network_changed
    }
}

impl Default for TorCircuitRotation {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Le seuil initial est dans la plage [512 KiB, 640 KiB).
    #[test]
    fn test_rotation_new_has_jittered_threshold() {
        for _ in 0..100 {
            let rot = TorCircuitRotation::new();
            let t = rot.current_volume_threshold();
            assert!(
                t >= VOLUME_BASE_BYTES && t < VOLUME_BASE_BYTES + VOLUME_JITTER_MAX_BYTES,
                "seuil {t} hors plage [{VOLUME_BASE_BYTES}, {})",
                VOLUME_BASE_BYTES + VOLUME_JITTER_MAX_BYTES
            );
        }
    }

    /// Rotation déclenchée quand le volume cumulé atteint le seuil.
    #[test]
    fn test_rotation_triggers_on_volume() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();
        let threshold = rot.current_volume_threshold();

        rot.record_bytes_sent(threshold - 1);
        assert!(rot.should_rotate(now).is_none(), "pas encore au seuil");

        rot.record_bytes_sent(1);
        assert_eq!(
            rot.should_rotate(now),
            Some(RotationReason::VolumeThreshold),
            "seuil atteint → rotation"
        );
    }

    /// Pas de rotation sous le seuil (avec activité récente).
    #[test]
    fn test_rotation_does_not_trigger_below_volume() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();
        let threshold = rot.current_volume_threshold();

        rot.record_bytes_sent(threshold / 2);
        assert!(rot.should_rotate(now).is_none());
    }

    /// Rotation déclenchée après 15 s d'inactivité.
    #[test]
    fn test_rotation_triggers_on_inactivity() {
        let rot = TorCircuitRotation::new();
        let t0 = Instant::now();

        // Aucune activité depuis t0. À t0 + 15 s → rotation.
        let t_after = t0 + INACTIVITY_TIMEOUT;
        assert_eq!(
            rot.should_rotate(t_after),
            Some(RotationReason::Inactivity)
        );
    }

    /// Pas de rotation si l'activité est récente.
    #[test]
    fn test_rotation_does_not_trigger_on_activity() {
        let mut rot = TorCircuitRotation::new();
        let t0 = Instant::now();

        // Activité à t0 + 10 s (moins de 15 s).
        let t_active = t0 + Duration::from_secs(10);
        rot.record_activity(t_active);

        // Évaluation à t_active + 5 s → seulement 5 s d'inactivité.
        let t_check = t_active + Duration::from_secs(5);
        assert!(rot.should_rotate(t_check).is_none());
    }

    /// Rotation déclenchée après 3 erreurs consécutives.
    #[test]
    fn test_rotation_triggers_on_consecutive_errors() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();

        rot.record_error();
        assert!(rot.should_rotate(now).is_none(), "1 erreur, pas encore");

        rot.record_error();
        assert!(rot.should_rotate(now).is_none(), "2 erreurs, pas encore");

        rot.record_error();
        assert_eq!(
            rot.should_rotate(now),
            Some(RotationReason::ConsecutiveErrors),
            "3 erreurs → rotation"
        );
    }

    /// Le compteur d'erreurs est reset par un succès.
    #[test]
    fn test_rotation_error_count_resets_on_success() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();

        rot.record_error();
        rot.record_error();
        rot.record_success();
        assert_eq!(rot.consecutive_errors(), 0);

        // Une nouvelle erreur ne déclenche pas immédiatement.
        rot.record_error();
        assert!(rot.should_rotate(now).is_none());
    }

    /// Changement réseau → rotation immédiate (prioritaire sur volume/erreurs).
    #[test]
    fn test_rotation_network_change_forces_immediate() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();

        // Aucun volume, aucune erreur, activité récente.
        assert!(rot.should_rotate(now).is_none());

        rot.invalidate_on_network_change();
        assert_eq!(
            rot.should_rotate(now),
            Some(RotationReason::NetworkChange)
        );
    }

    /// Priorité : NetworkChange > ConsecutiveErrors > Volume > Inactivity.
    #[test]
    fn test_rotation_priority_order() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();

        // Tout cumulé : 3 erreurs + volume dépassé + inactivité + réseau changé.
        rot.record_error();
        rot.record_error();
        rot.record_error();
        rot.record_bytes_sent(rot.current_volume_threshold());
        rot.record_activity(now - Duration::from_secs(60)); // inactivité
        rot.invalidate_on_network_change();

        // NetworkChange doit gagner.
        assert_eq!(
            rot.should_rotate(now),
            Some(RotationReason::NetworkChange)
        );
    }

    /// Le jitter varie entre deux créations (probabiliste sur 100 itérations).
    #[test]
    fn test_rotation_jitter_varies_between_instances() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            seen.insert(TorCircuitRotation::new().current_volume_threshold());
        }
        // Sur 100 instances, au moins 5 valeurs distinctes attendues
        // (statistiquement, plage de 128K = 131072 valeurs possibles).
        assert!(
            seen.len() >= 5,
            "jitter peu varié : {} valeurs distinctes sur 100",
            seen.len()
        );
    }

    /// Après reset, un nouveau jitter est généré.
    #[test]
    fn test_rotation_reset_regenerates_threshold() {
        let mut rot = TorCircuitRotation::new();
        let t_old = rot.current_volume_threshold();

        // Reset plusieurs fois et vérifier que le seuil change.
        let now = Instant::now();
        let mut changed = false;
        for _ in 0..100 {
            rot.reset_after_rotation(now);
            if rot.current_volume_threshold() != t_old {
                changed = true;
                break;
            }
        }
        assert!(changed, "le seuil ne change pas après reset");
    }

    /// Après reset, l'état est propre (volume=0, erreurs=0, network_changed=false).
    #[test]
    fn test_rotation_reset_clears_state() {
        let mut rot = TorCircuitRotation::new();
        let now = Instant::now();

        rot.record_bytes_sent(1_000_000);
        rot.record_error();
        rot.record_error();
        rot.invalidate_on_network_change();

        rot.reset_after_rotation(now);

        assert_eq!(rot.bytes_since_rotation(), 0);
        assert_eq!(rot.consecutive_errors(), 0);
        assert!(!rot.network_changed());
        assert!(rot.should_rotate(now).is_none());
    }

    /// `RotationReason::as_str()` retourne des chaînes distinctes.
    #[test]
    fn test_rotation_reason_as_str() {
        assert_eq!(RotationReason::VolumeThreshold.as_str(), "volume_threshold");
        assert_eq!(RotationReason::Inactivity.as_str(), "inactivity");
        assert_eq!(RotationReason::NetworkChange.as_str(), "network_change");
        assert_eq!(RotationReason::ConsecutiveErrors.as_str(), "consecutive_errors");
    }

    /// `Default` équivaut à `new()`.
    #[test]
    fn test_rotation_default_impl() {
        let rot = TorCircuitRotation::default();
        assert_eq!(rot.bytes_since_rotation(), 0);
        assert_eq!(rot.consecutive_errors(), 0);
        assert!(!rot.network_changed());
        // Le seuil doit être dans la plage.
        let t = rot.current_volume_threshold();
        assert!(t >= VOLUME_BASE_BYTES);
        assert!(t < VOLUME_BASE_BYTES + VOLUME_JITTER_MAX_BYTES);
    }
}