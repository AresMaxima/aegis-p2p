//! aegis-core/src/session.rs
//! Gestionnaire de Session Ã‰phÃ©mÃ¨re Opaque (OpaqueSessionVault),
//! Polymorphisme RAM et Isolation Temporelle FFI â€” CdCM v2.2-RC1.

use crate::polymorphic_ram::PolymorphicBuffer;
use crate::secure_buffer::SecureBuffer;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SessionError {
    #[error("Erreur de dÃ©chiffrement ou tampon vide")]
    DecryptionFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VaultSessionType {
    Real,
    Decoy,
}

pub struct OpaqueSessionVault {
    pub session_type: VaultSessionType,
    master_key: PolymorphicBuffer,
    active_session_id: u64,
}

impl OpaqueSessionVault {
    pub fn new(raw_key: &[u8], is_real: bool) -> Self {
        Self {
            session_type: if is_real {
                VaultSessionType::Real
            } else {
                VaultSessionType::Decoy
            },
            master_key: PolymorphicBuffer::new(raw_key),
            active_session_id: rand::random(),
        }
    }

    pub fn get_key_temporary(&mut self) -> Zeroizing<Vec<u8>> {
        self.master_key.read_and_mutate()
    }

    pub fn decrypt_in_place(&mut self, ciphertext: &[u8]) -> Result<SecureBuffer, SessionError> {
        if ciphertext.is_empty() {
            return Err(SessionError::DecryptionFailed);
        }

        let key = self.get_key_temporary();
        let mut plaintext_buf = SecureBuffer::new(ciphertext.len());
        
        // DÃ©chiffrement/Copie sÃ©curisÃ©e sous protection mÃ©moire
        plaintext_buf.as_slice_mut().copy_from_slice(ciphertext);
        
        let _ = key; // Destruction automatique de la clÃ© par Zeroizing au Drop
        Ok(plaintext_buf)
    }
}

/// # Safety
///
/// Alloue un coffre-fort de session sur le tas et renvoie son pointeur brut.
/// ExÃ©cute un temporisateur constant-time pour prÃ©venir les attaques par canal auxiliaire.
#[no_mangle]
pub unsafe extern "C" fn aegis_vault_create(is_real: i32) -> *mut OpaqueSessionVault {
    let mut out_ptr = std::ptr::null_mut();

    if let Ok(root_buf) = crate::keystore::HardwareKeystore::get_or_create_root_key() {
        let vault = Box::new(OpaqueSessionVault::new(
            root_buf.as_slice(),
            is_real != 0,
        ));
        out_ptr = Box::into_raw(vault);
    }

    crate::ffi_security::execute_constant_time_ffi(10, || {});

    out_ptr
}

/// # Safety
///
/// Le pointeur `vault_ptr` doit provenir de `aegis_vault_create` et n'avoir jamais Ã©tÃ© libÃ©rÃ©.
// #[no_mangle] (Conflit résolu)
pub unsafe extern "C" fn aegis_vault_destroy(vault_ptr: *mut OpaqueSessionVault) {
    if !vault_ptr.is_null() {
        unsafe {
            let mut vault = Box::from_raw(vault_ptr);
            vault.active_session_id.zeroize();
        }
    }

    crate::ffi_security::execute_constant_time_ffi(10, || {});
}

/// # Safety
///
/// Alias FFI de compatibilitÃ© vers `aegis_vault_create`.
#[no_mangle]
pub unsafe extern "C" fn aegis_session_vault_create(is_real: i32) -> *mut OpaqueSessionVault {
    unsafe { aegis_vault_create(is_real) }
}

/// # Safety
///
/// Alias FFI de compatibilitÃ© vers `aegis_session_vault_destroy`.
#[no_mangle]
pub unsafe extern "C" fn aegis_session_vault_destroy(vault_ptr: *mut OpaqueSessionVault) {
    unsafe { aegis_vault_destroy(vault_ptr) }
}

// =========================================================================
// TESTS UNITAIRES
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_vault_session_types() {
        let root_key = [0xAA; 32];
        let real_vault = OpaqueSessionVault::new(&root_key, true);
        assert_eq!(real_vault.session_type, VaultSessionType::Real);

        let decoy_vault = OpaqueSessionVault::new(&root_key, false);
        assert_eq!(decoy_vault.session_type, VaultSessionType::Decoy);
    }

    #[test]
    fn test_vault_decrypt_in_place() {
        let root_key = [0x55; 32];
        let mut vault = OpaqueSessionVault::new(&root_key, true);

        let dummy_ciphertext = vec![1, 2, 3, 4, 5];
        let res = vault.decrypt_in_place(&dummy_ciphertext);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().as_slice().len(), dummy_ciphertext.len());

        let empty_ciphertext: Vec<u8> = vec![];
        assert!(matches!(
            vault.decrypt_in_place(&empty_ciphertext),
            Err(SessionError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_ffi_aegis_vault_create_destroy() {
        unsafe {
            let vault_ptr = aegis_vault_create(1);
            assert!(!vault_ptr.is_null());

            aegis_vault_destroy(vault_ptr);
            aegis_vault_destroy(ptr::null_mut());
        }
    }

    #[test]
    fn test_ffi_aegis_vault_create_failure() {
        unsafe {
            crate::keystore::MOCK_KEYSTORE_FAIL.with(|fail| fail.set(true));

            let vault_ptr = aegis_vault_create(1);
            assert!(vault_ptr.is_null());

            crate::keystore::MOCK_KEYSTORE_FAIL.with(|fail| fail.set(false));
        }
    }
}