#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { if data.len() >= 32 { let _ = aegis_core::aegis_v36_wipe_ephemeral_buffers(); let _ = unsafe { aegis_core::aegis_deaddrop_deposit(data.as_ptr(), data[32..].as_ptr(), data.len() - 32) }; } });
