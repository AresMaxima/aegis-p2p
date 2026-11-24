#![no_main]
use libfuzzer_sys::fuzz_target;
use aegis_core::network::stealth_transport::{decode_quic_varint, unwrap_cell_masque_h3};
fuzz_target!(|data: &[u8]| { let _ = decode_quic_varint(data); let _ = unwrap_cell_masque_h3(&[0x55u8; 32], data); });
