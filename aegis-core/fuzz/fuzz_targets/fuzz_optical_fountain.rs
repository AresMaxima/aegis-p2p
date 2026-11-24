#![no_main]
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
fuzz_target!(|data: &[u8]| { if let Ok(s) = std::str::from_utf8(data) { if let Ok(c) = CString::new(s) { let mut out = [0u8; 1024]; let mut l = 0usize; let _ = unsafe { aegis_core::aegis_optical_ingest_droplet(c.as_ptr(), out.as_mut_ptr(), out.len(), &mut l) }; } } });
