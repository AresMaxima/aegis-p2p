pub mod integrity;
pub mod keys;
pub mod memory;
pub mod ratchet;

// Module TPM — compilé uniquement avec `--features tpm`.
// Sans la feature, le module est absent du crate (aucun impact sur la
// prod, car `tpm` n'est utilisé par aucun autre module).
#[cfg(feature = "tpm")]
pub mod tpm;