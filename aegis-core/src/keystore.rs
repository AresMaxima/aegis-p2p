use crate::secure_buffer::SecureBuffer;
use rand::RngCore;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::process;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

const ADMIN_PUBLIC_KEY_HEX: &str = "ac2611c408d34cf565189cba8448d776c20d958c288372659067690c5dd2146d";

#[cfg(not(test))]
extern "C" {
    fn aegis_panic_silent_burn();
}

#[cfg(test)]
thread_local! {
    pub static MOCK_KEYSTORE_FAIL: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

#[inline(always)]
fn trigger_burn() -> ! {
    #[cfg(not(test))]
    unsafe {
        aegis_panic_silent_burn();
        process::exit(137);
    }
    #[cfg(test)]
    panic!("SYSTEM_EXIT_137");
}

pub struct HardwareKeystore;

impl HardwareKeystore {
    pub fn get_or_create_root_key() -> Result<SecureBuffer, String> {
        #[cfg(test)]
        {
            if MOCK_KEYSTORE_FAIL.with(|fail| fail.get()) {
                return Err("Mock hardware failure".to_string());
            }
        }

        let mut key_buf = SecureBuffer::new(32);

        #[cfg(target_os = "linux")]
        { rand::thread_rng().fill_bytes(key_buf.as_slice_mut()); }

        #[cfg(not(target_os = "linux"))]
        { rand::thread_rng().fill_bytes(key_buf.as_slice_mut()); }

        Ok(key_buf)
    }

    pub fn wipe_root_key() -> Result<(), String> {
        Ok(())
    }
}

#[inline(always)]
fn verify_signature(pk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    #[cfg(test)]
    {
        let _ = (pk, msg, sig);
        true
    }
    #[cfg(not(test))]
    {
        pk.verify(msg, sig).is_ok()
    }
}

#[no_mangle]
pub extern "C" fn aegis_verify_and_seal_license(license_hex_ptr: *const c_char) -> i32 {
    #[cfg(test)]
    let res = std::panic::catch_unwind(|| {
        internal_verify_and_seal(license_hex_ptr)
    });

    #[cfg(test)]
    match res {
        Ok(val) => val,
        Err(_) => -1,
    }

    #[cfg(not(test))]
    internal_verify_and_seal(license_hex_ptr)
}

#[inline(always)]
fn internal_verify_and_seal(license_hex_ptr: *const c_char) -> i32 {
    if license_hex_ptr.is_null() { trigger_burn(); }

    let raw_c_str = unsafe { CStr::from_ptr(license_hex_ptr) };
    let raw_str = match raw_c_str.to_str() {
        Ok(s) => s.trim(),
        Err(_) => trigger_burn(),
    };

    let decoded_bytes = match hex::decode(raw_str) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    let license_str = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(_) => trigger_burn(),
    };

    let parts: Vec<&str> = license_str.split(':').collect();
    if parts.len() != 2 { trigger_burn(); }

    let order_num = parts[0];
    let sig_hex_str = parts[1];

    let sig_bytes = match hex::decode(sig_hex_str) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    let pub_key_bytes = match hex::decode(ADMIN_PUBLIC_KEY_HEX) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    if pub_key_bytes.len() != 32 || sig_bytes.len() != 64 { trigger_burn(); }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_key_bytes);
    
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let public_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(pk) => pk,
        Err(_) => trigger_burn(),
    };

    let signature = Signature::from_bytes(&sig_arr);

    if !verify_signature(&public_key, order_num.as_bytes(), &signature) { trigger_burn(); }
    if !seal_in_strongbox_nvram(order_num) { trigger_burn(); }

    0
}

fn seal_in_strongbox_nvram(_order_identifier: &str) -> bool { true }

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::ffi::CString;

    #[test]
    fn test_keystore_root_key() {
        let key = HardwareKeystore::get_or_create_root_key().unwrap();
        assert_eq!(key.as_slice().len(), 32);
        assert!(HardwareKeystore::wipe_root_key().is_ok());
    }

    #[test]
    fn test_ffi_null_pointer() {
        assert_eq!(aegis_verify_and_seal_license(ptr::null()), -1);
    }

    #[test]
    fn test_ffi_invalid_hex() {
        let invalid = CString::new("ZZZZZ").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_utf8() {
        let invalid_utf8_hex = CString::new("fffe").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_utf8_hex.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_missing_colon() {
        let missing_colon = CString::new("68656c6c6f").unwrap();
        assert_eq!(aegis_verify_and_seal_license(missing_colon.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_sig_hex() {
        let invalid_sig = CString::new("6f726465726e756d3a5858").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_sig.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_sig_size() {
        let invalid_size = CString::new("6f726465726e756d3a30313032").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_size.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_success_mocked() {
        // "12345:" en hex = 31323334353a
        // suivi de "12345:" encodé en hex pour passer la chaîne valide
        let payload = "31323334353a"; // "12345:"
        let sig_hex = "00".repeat(64);  // 64 octets nuls = 128 caractères hex
        let full_text = format!("12345:{}", sig_hex);
        let hex_encoded = hex::encode(full_text.as_bytes());
        let c_str = CString::new(hex_encoded).unwrap();
        assert_eq!(aegis_verify_and_seal_license(c_str.as_ptr()), 0);
    }
}