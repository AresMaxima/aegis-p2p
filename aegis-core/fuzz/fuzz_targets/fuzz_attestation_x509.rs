#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let pk = [0x42u8; 32]; let n = [0x99u8; 32]; let _ = unsafe { aegis_core::aegis_verify_peer_attestation(data.as_ptr(), data.len(), pk.as_ptr(), n.as_ptr(), false) }; });
