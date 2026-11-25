use std::sync::Mutex;
use zeroize::Zeroize;
use crate::crypto::pq_ratchet::ContinuousPqRatchet;

static NFC_FALLBACK_BUF: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
static SPQR_LIVE_PAIR: Mutex<Option<(ContinuousPqRatchet, ContinuousPqRatchet)>> = Mutex::new(None);

#[no_mangle]
pub extern "C" fn aegis_clear_external_nfc_token_secret() -> i32 {
    if let Ok(mut spqr) = SPQR_LIVE_PAIR.lock() {
        *spqr = None; // ZeroizeOnDrop detruit root_key, chain_keys et pending_dk_bytes en RAM
    }
    let Ok(mut g) = NFC_FALLBACK_BUF.lock() else { return -1 };
    g.zeroize();
    std::hint::black_box(&*g);
    0
}

#[no_mangle]
pub extern "C" fn aegis_spqr_run_pcs_epoch_selfcheck() -> i32 {
    let Ok(mut guard) = SPQR_LIVE_PAIR.lock() else { return -1 };
    if guard.is_none() {
        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() { return -1; }
        let a = ContinuousPqRatchet::new(&seed, true);
        let b = ContinuousPqRatchet::new(&seed, false);
        seed.zeroize();
        *guard = Some((a, b));
    }
    let (a, b) = guard.as_mut().unwrap();
    let mut comp = b.clone_for_pcs_audit();

    let Ok(ek) = a.initiate_pq_step() else { return -2 };
    let mut ct_opt = None;
    for c in &ek {
        match b.process_control_cell(c) {
            Ok(Some(r)) => ct_opt = Some(r),
            Ok(None) => {}
            Err(_) => return -3,
        }
    }
    let Some(ct) = ct_opt else { return -4 };
    for c in &ct {
        if a.process_control_cell(c).is_err() { return -5; }
    }
    let Ok(s) = a.seal_cell(b"SPQR-OK") else { return -6 };
    if comp.open_cell(&s).is_ok() { return -7; }
    match b.open_cell(&s) {
        Ok(pt) if pt == b"SPQR-OK" => a.pq_epoch as i32,
        _ => -8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_stealth_wrap_h3_cell(k: *const u8, c: *const u8, out: *mut u8, cap: usize, w: *mut usize) -> i32 {
    if k.is_null() || c.is_null() || out.is_null() || w.is_null() { return -1; }
    let (mut key, mut cell) = ([0u8; 32], [0u8; 512]);
    key.copy_from_slice(std::slice::from_raw_parts(k, 32));
    cell.copy_from_slice(std::slice::from_raw_parts(c, 512));
    let res = crate::network::stealth_transport::wrap_cell_masque_h3(&key, &cell);
    key.zeroize(); cell.zeroize();
    let Ok(wire) = res else { return -2 };
    if wire.len() > cap { return -3; }
    std::ptr::copy_nonoverlapping(wire.as_ptr(), out, wire.len()); *w = wire.len(); 0
}

#[no_mangle]
pub unsafe extern "C" fn aegis_stealth_unwrap_h3_cell(k: *const u8, w: *const u8, wlen: usize, out512: *mut u8) -> i32 {
    if k.is_null() || w.is_null() || out512.is_null() { return -1; }
    let mut key = [0u8; 32];
    key.copy_from_slice(std::slice::from_raw_parts(k, 32));
    let wire = std::slice::from_raw_parts(w, wlen);
    let res = crate::network::stealth_transport::unwrap_cell_masque_h3(&key, wire);
    key.zeroize();
    let Ok(mut plain) = res else { return -2 };
    std::ptr::copy_nonoverlapping(plain.as_ptr(), out512, 512);
    plain.zeroize();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_v37_ffi_spqr_and_masque() {
        let _ = aegis_clear_external_nfc_token_secret();
        assert_eq!(aegis_spqr_run_pcs_epoch_selfcheck(), 1);
        assert_eq!(aegis_spqr_run_pcs_epoch_selfcheck(), 2);
        assert_eq!(aegis_spqr_run_pcs_epoch_selfcheck(), 3);
        let (k, c, mut out, mut r, mut n) = ([7u8; 32], [9u8; 512], [0u8; 768], [0u8; 512], 0usize);
        assert_eq!(unsafe { aegis_stealth_wrap_h3_cell(k.as_ptr(), c.as_ptr(), out.as_mut_ptr(), 768, &mut n) }, 0);
        assert_eq!(unsafe { aegis_stealth_unwrap_h3_cell(k.as_ptr(), out.as_ptr(), n, r.as_mut_ptr()) }, 0);
        assert_eq!(c, r);
    }
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test] fn test_proc_self_mem_physical_zeroize_proof() {
        use std::io::{Read, Seek, SeekFrom};
        let mut secret = Box::new(*b"AEGIS_CANARY_HIGH_ENTROPY_SECRET_KEY_MATERIAL_MLKEM1024_LIVE_RAM");
        let addr = (&*secret as *const [u8; 64]) as usize as u64;
        let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
        let mut probe = [0u8; 64];
        mem.seek(SeekFrom::Start(addr)).unwrap(); mem.read_exact(&mut probe).unwrap();
        assert_eq!(&probe, &*secret);
        secret.zeroize(); std::hint::black_box(&secret);
        mem.seek(SeekFrom::Start(addr)).unwrap(); mem.read_exact(&mut probe).unwrap();
        assert_eq!(probe, [0u8; 64]);
    }
}