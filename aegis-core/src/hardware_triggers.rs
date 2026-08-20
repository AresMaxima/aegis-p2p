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
#[no_mangle]
pub unsafe extern "C" fn aegis_hardware_trigger_panic(code: i32) {
    match code {
        1 => HardwareTriggerMonitor::on_storage_tampered(),
        2 => HardwareTriggerMonitor::on_usb_tampered(),
        3 => HardwareTriggerMonitor::on_motion_emergency(),
        _ => PanicPurge::execute_silent_burn(),
    }
}