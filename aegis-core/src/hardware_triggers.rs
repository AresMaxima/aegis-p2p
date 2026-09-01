//! aegis-core/src/hardware_triggers.rs
//! Monitoring des Capteurs Matériels et Triggers d'Urgence (CdCM v2.2-RC1).

use crate::panic::PanicPurge;

pub struct HardwareTriggerMonitor;

impl HardwareTriggerMonitor {
    /// Déclenché en cas de retrait brutal de la carte SIM ou du stockage externe
    pub fn on_storage_tampered() -> ! {
        PanicPurge::execute_silent_burn();
    }

    /// Déclenché lors d'une déconnexion USB suspecte pendant une session active
    pub fn on_usb_tampered() -> ! {
        PanicPurge::execute_silent_burn();
    }

    /// Déclenché par une séquence d'accéléromètre spécifique (mouvement de crise)
    pub fn on_motion_emergency() -> ! {
        PanicPurge::execute_silent_burn();
    }
}

/// Point d'entrée FFI appelé lors de la détection d'une anomalie matérielle sous Android/Linux
///
/// # Safety
///
/// Cette fonction est un point d'entrée FFI `unsafe`. Le paramètre `code` doit indiquer le type
/// d'anomalie détectée. Si `code` est non nul, la fonction exécute immédiatement un effacement d'urgence
/// et termine le processus système de manière irréversible.
#[no_mangle]
pub unsafe extern "C" fn aegis_hardware_trigger_panic(code: i32) {
    if code == 0 {
        return;
    }

    match code {
        1 => HardwareTriggerMonitor::on_storage_tampered(),
        2 => HardwareTriggerMonitor::on_usb_tampered(),
        3 => HardwareTriggerMonitor::on_motion_emergency(),
        _ => PanicPurge::execute_silent_burn(),
    }
}

// =========================================================================
// TESTS UNITAIRES
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_hardware_trigger_zero_code() {
        // Un code 0 ne doit pas déclencher la purge
        unsafe {
            aegis_hardware_trigger_panic(0);
        }
    }
}