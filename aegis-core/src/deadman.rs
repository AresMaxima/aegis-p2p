use crate::panic::PanicPurge;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_HEARTBEAT: AtomicU64 = AtomicU64::new(0);
static MAX_INACTIVITY_SECS: AtomicU64 = AtomicU64::new(86400); // 24 heures par défaut

pub struct DeadMansSwitch;

impl DeadMansSwitch {
    /// Enregistre un battement de cœur (réinitialise le minuteur lors d'un accès légitime)
    pub fn heartbeat() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        LAST_HEARTBEAT.store(now, Ordering::SeqCst);
    }

    /// Configuration du délai maximal avant auto-destruction matérielle (en secondes)
    pub fn set_max_inactivity(secs: u64) {
        MAX_INACTIVITY_SECS.store(secs, Ordering::SeqCst);
    }

    /// Contrôle l'échéance d'inactivité et déclenche immédiatement le Silent Burn si dépassée
    pub fn evaluate_or_burn() {
        let last = LAST_HEARTBEAT.load(Ordering::SeqCst);
        if last == 0 {
            return; // Minuteur non armé
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let max = MAX_INACTIVITY_SECS.load(Ordering::SeqCst);
        if now.saturating_sub(last) > max {
            PanicPurge::execute_silent_burn();
        }
    }
}

/// Point d'entrée FFI pour réinitialiser le minuteur lors du déverrouillage UI
#[no_mangle]
pub unsafe extern "C" fn aegis_deadman_heartbeat() {
    DeadMansSwitch::heartbeat();
}

/// Point d'entrée FFI appelé au lancement de l'application ou par tâche de fond
#[no_mangle]
pub unsafe extern "C" fn aegis_deadman_check() {
    DeadMansSwitch::evaluate_or_burn();
}

/// Permet d'ajuster dynamiquement le délai d'urgence (ex: 12h, 24h, 48h)
#[no_mangle]
pub unsafe extern "C" fn aegis_deadman_set_timeout(secs: u64) {
    DeadMansSwitch::set_max_inactivity(secs);
}