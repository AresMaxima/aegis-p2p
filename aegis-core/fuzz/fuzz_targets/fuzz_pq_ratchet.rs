#![no_main]
use libfuzzer_sys::fuzz_target;
use aegis_core::crypto::pq_ratchet::{ContinuousPqRatchet, SpqrFragmentAssembler};
fuzz_target!(|data: &[u8]| { if data.len() >= 512 { let mut c = [0u8; 512]; c.copy_from_slice(&data[..512]); let mut a = SpqrFragmentAssembler::new(); let _ = a.ingest_cell(&c); let mut r = ContinuousPqRatchet::new(&[0x11u8; 32], false); let _ = r.process_control_cell(&c); let _ = r.open_cell(&c); } });
