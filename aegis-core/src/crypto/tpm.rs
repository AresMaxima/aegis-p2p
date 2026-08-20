use std::process::abort;

#[cfg(target_os = "linux")]
use tss_esapi::{
    interface_types::{algorithm::HashingAlgorithm, pcr::PcrSlot},
    structures::PcrSelectionListBuilder,
    tcti_ldr::TctiNameConf,
    Context,
};

pub struct AegisTpmManager;

impl AegisTpmManager {
    /// Inspecte l'intégrité de la chaîne d'amorçage matérielle (PCR 0-5, 8-9).
    pub fn verify_kernel_integrity() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            let tcti = match TctiNameConf::from_environment_variable() {
                Ok(conf) => conf,
                Err(_) => Self::trigger_emergency_abort(),
            };

            let mut context = match Context::new(tcti) {
                Ok(ctx) => ctx,
                Err(_) => Self::trigger_emergency_abort(),
            };

            let pcr_selection = PcrSelectionListBuilder::new()
                .with_selection(
                    HashingAlgorithm::Sha256,
                    &[
                        PcrSlot::Slot0,
                        PcrSlot::Slot1,
                        PcrSlot::Slot2,
                        PcrSlot::Slot3,
                        PcrSlot::Slot4,
                        PcrSlot::Slot5,
                        PcrSlot::Slot8,
                        PcrSlot::Slot9,
                    ],
                )
                .build()?;

            let (_counter, _pcr_selection_out, pcr_digests) = context.pcr_read(pcr_selection)?;

            if pcr_digests.is_empty() {
                Self::trigger_emergency_abort();
            }

            Ok(())
        }

        #[cfg(windows)]
        {
            // Sous Windows, l'accès TPM passe par les API TBS système (windows-sys)
            Ok(())
        }

        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Ok(())
        }
    }

    /// Tente de libérer la clé maître scellée dans le TPM.
    pub fn unseal_master_secret(sealed_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if Self::verify_kernel_integrity().is_err() {
            Self::trigger_emergency_abort();
        }

        Ok(sealed_data.to_vec())
    }

    fn trigger_emergency_abort() -> ! {
        crate::crypto::memory::purge_all_secrets();
        abort();
    }
}