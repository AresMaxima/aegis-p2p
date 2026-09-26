#![no_main]
use libfuzzer-sys::fuzz_target;
use aegis_core::crypto_pq::process_512b_frame_ephemeral;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 + 8 + 512 {
        let master_key = &data[0..32];
        let frame_index = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let mut payload = [0u8; 512];
        payload.copy_from_slice(&data[40..552]);
        let _ = process_512b_frame_ephemeral(master_key, frame_index, &mut payload);
    }
});
