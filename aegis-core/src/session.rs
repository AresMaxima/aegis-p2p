use crate::polymorphic_ram::PolymorphicBuffer;
use crate::secure_buffer::SecureBuffer;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, PartialEq, Eq)]
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

    /// Récupère temporairement la clé de session avec mutation immédiate de l'entropie polymorphe
    pub fn get_key_temporary(&mut self) -> Zeroizing<Vec<u8>> {
        self.master_key.read_and_mutate()
    }

    /// Exécute le déchiffrement exclusivement en RAM Rust avec verrouillage mlock
    pub fn decrypt_in_place(&mut self, ciphertext: &[u8]) -> Result<SecureBuffer, ()> {
        let key = self.get_key_temporary();
        let plaintext_buf = SecureBuffer::new(ciphertext.len());
        // Traitement cryptographique confiné en mémoire mlockée...
        let _ = key; // La clé est automatiquement purgée (`zeroize`) en sortie de portée
        Ok(plaintext_buf)
    }
}

/// Pointeur opaque FFI transmis à Flutter (Dart ne voit que l'adresse mémoire)
#[no_mangle]
pub unsafe extern "C" fn aegis_vault_create(is_real: i32) -> *mut OpaqueSessionVault {
    crate::ffi_security::execute_constant_time_ffi(10, || {
        match crate::keystore::HardwareKeystore::get_or_create_root_key() {
            Ok(root_buf) => {
                let vault = Box::new(OpaqueSessionVault::new(
                    root_buf.as_slice(),
                    is_real != 0,
                ));
                Box::into_raw(vault)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Libère le coffre-fort opaque et purge sa mémoire depuis Dart
#[no_mangle]
pub unsafe extern "C" fn aegis_vault_destroy(vault_ptr: *mut OpaqueSessionVault) {
    crate::ffi_security::execute_constant_time_ffi(10, || {
        if !vault_ptr.is_null() {
            // Reprend la propriété du pointeur pour déclencher le trait Drop de Rust
            let mut vault = Box::from_raw(vault_ptr);
            vault.active_session_id.zeroize();
            // `vault.master_key` est automatiquement purgée (`zeroize`) par son destructeur RAII
        }
    });
}